#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
import struct
import time
import os
import asyncore
import socket
import sys
import collections
import threading
import Queue
import configobj
import imp
import signal
import validate
import syslog
import traceback
import fcntl
import errno
from nflogipac.asynschedcore import asynschedcore, periodic
from nflogipac.syslogging import SysloggingDebugLevel

try:
	from nflogipac.paths import nflogipacd as nflogipacd_path
except ImportError:  # running from source directory
	nflogipacd_path = "./nflogipacd"

try:
	from setproctitle import setproctitle
except ImportError, exc:
	def setproctitle(_):  # make this ImportError lazy
		raise exc


class FatalError(Exception):
	"""Something very bad happend leading to program abort with a message."""


def set_close_on_exec(filedescriptor):
	flags = fcntl.fcntl(filedescriptor, fcntl.F_GETFD)
	fcntl.fcntl(filedescriptor, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)


def create_counter(group, kind):
	"""
	@type group: int
	@type kind: str
	@rtype: (int, socket)
	@returns: (pid, stdin_and_stdout)
	"""
	parentsock, childsock = socket.socketpair()  # for communication
	parentpipe, childpipe = os.pipe()  # for startup
	pid = os.fork()
	if 0 == pid:  # child
		try:
			parentsock.close()
			os.close(parentpipe)
			# close signals
			set_close_on_exec(childpipe)
			os.close(0)
			os.close(1)
			os.dup2(childsock.fileno(), 0)
			os.dup2(childsock.fileno(), 1)
			try:
				os.execv(nflogipacd_path, [nflogipacd_path, "%d" % group, kind])
			except OSError, err:
				os.write(childpipe, "exec failed with OSError: %s" % str(err))
				sys.exit(1)
		except Exception, exc:
			os.write(childpipe, "something in the child went wrong badly: %s" %
					 str(exc))
			sys.exit(1)
		os.write(childpipe, "this is unreachable code")
		sys.exit(1)

	# parent
	childsock.close()
	os.close(childpipe)
	report = os.read(parentpipe, 4096)
	os.close(parentpipe)
	if report:
		raise FatalError(report)
	return pid, parentsock


class Counter(asyncore.dispatcher):
	def __init__(self, group, kind, map=None):
		"""
		@type group: int
		@type kind: str
		"""
		self.group = group
		self.kind = kind
		self.pid, counter_sock = create_counter(group, kind)
		asyncore.dispatcher.__init__(self, sock=counter_sock, map=map)
		self.requesting_data = False
		self.lastrequest = 0
		self.buf = ""

	def request_data(self):
		self.requesting_data = True

	def writable(self):
		return self.requesting_data

	def handle_write(self):
		if self.send("x"):
			self.lastrequest = time.time()
			self.requesting_data = False

	def readable(self):
		return True

	def handle_close(self):
		self.close()

	def handle_read(self):
		self.buf += self.recv(8192)
		while len(self.buf) >= 4:
			length, command = struct.unpack("!HH", self.buf[:4])
			if len(self.buf) < length:
				break
			self.handle_packet(command, self.buf[4:length])
			self.buf = self.buf[length:]

	def handle_packet(self, command, content):
		if command == 1:
			if len(content) < 8:
				self.close()
				return
			value, = struct.unpack("!Q", content[:8])
			addr = content[8:]
			self.handle_cmd_update(self.lastrequest, addr, value)
		elif command == 2:
			if content != "":
				self.close()
				return
			self.handle_cmd_end()
		elif command == 3:
			if len(content) != 2:
				self.close()
				return
			losscount, = struct.unpack("!H", content)
			self.handle_cmd_loss(self.lastrequest, losscount)
		else:
			self.close()

	def handle_cmd_update(self, timestamp, addr, value):
		"""
		@type timestamp: float
		@type addr: str
		@type value: int or long
		"""
		raise NotImplementedError

	def handle_cmd_end(self):
		raise NotImplementedError

	def handle_cmd_loss(self, timestamp, count):
		"""
		@type timestamp: float
		@type addr: str
		"""
		raise NotImplementedError


class DebugCounter(Counter):
	def __init__(self, *args, **kwargs):
		Counter.__init__(self, *args, **kwargs)
		self.pending = collections.defaultdict(long)

	def handle_cmd_update(self, timestamp, addr, value):
		self.pending[addr] += value
		print("received update for group %d addr %s value %d" %
			  (self.group, addr.encode("hex"), value))

	def handle_cmd_end(self):
		print("end %r" % (self.pending,))

	def handle_cmd_loss(self, timestamp, count):
		print("lost at least %d segments" % count)


class ReportingCounter(Counter):
	def __init__(self, group, kind, writefunc, endfunc, lossfunc, map=None):
		"""
		@type group: int
		@type kind: str
		@type writefunc: (float, int, str, int) -> None
		@param writefunc: is a function taking a timestamp, a group, a binary
				IP (4 or 6) address and a byte count. It must not block or fail.
		@type endfunc: int -> None
		@param endfunc takes a group
		@type lossfunc: (float, int, int) -> None
		@param lossfunc: takes a timestamp, a group and a count
		"""
		Counter.__init__(self, group, kind, map)
		self.writefunc = writefunc
		self.endfunc = endfunc
		self.lossfunc = lossfunc

	def handle_cmd_update(self, timestamp, addr, value):
		self.writefunc(timestamp, self.group, addr, value)

	def handle_cmd_end(self):
		self.endfunc(self.group)

	def handle_cmd_loss(self, timestamp, count):
		self.lossfunc(timestamp, self.group, count)


class GatherThread(threading.Thread):
	def __init__(self, pinginterval, wt, log):
		"""
		@type pinginterval: int
		@type wt: WriteThread
		"""
		threading.Thread.__init__(self)
		self.wt = wt
		self.log = log
		self.asc = asynschedcore({})
		self.periodic = periodic(self.asc, pinginterval, 0, self.periodically)
		self.counters = {}
		self.counters_working = set()
		self.terminating = False

	def add_counter(self, group, kind):
		"""
		@type group: int
		@type kind: str
		"""
		assert group not in self.counters
		self.counters[group] = ReportingCounter(group, kind, self.wt.account,
												self.end_hook, self.wt.notice_loss, self.asc.asynmap)

	def request_data(self):
		self.wt.start_write()
		self.counters_working = set(self.counters.keys())
		for counter in self.counters.values():
			counter.request_data()

	def end_hook(self, group):
		self.counters_working.remove(group)
		if not self.counters_working:
			self.log.log_debug("received end packet from all counters", 1)
			self.wt.end_write()
		if self.terminating:
			self.counters.pop(group).close()

	def periodically(self):
		self.log.log_debug("querying counters", 2)
		self.request_data()
		if not self.counters:
			self.periodic.stop()

	def run(self):
		if self.counters:
			self.periodic.schedule()
		self.asc.run()

	def ping_now(self):
		self.periodic.call_now()

	def terminate(self):
		self.periodic.stop()
		if not self.terminating:
			self.request_data()
			self.terminating = True

	def handle_child_death(self, pid):
		"""
		@type pid: int
		@rtype: bool
		@returns: whether the child was a counter
		"""
		for group, counter in self.counters.items():
			if counter.pid != pid:
				continue
			if self.terminating:
				self.log.log_notice("child pid:%d group:%d terminated" %
									(pid, group))
			else:
				self.log.log_err("child pid:%d group:%d unexpectedly died" %
								 (pid, group))
			try:
				self.counters_working.remove(group)
			except KeyError:
				pass
			else:
				# only executed if group was actually removed
				if not self.counters_working:
					self.wt.end_write()
			self.counters.pop(group).close()
			return True
		return False

	def handle_sigchld(self):
		while True:
			try:
				pid, status = os.waitpid(-1, os.WNOHANG)
			except OSError, err:
				if err.args[0] == errno.ECHILD:  # suppress ECHILD
					return
				raise
			if pid == 0:
				return
			if self.handle_child_death(pid):
				self.terminate()


class WriteThread(threading.Thread):
	def __init__(self, writeplugin, log):
		threading.Thread.__init__(self)
		self.queue = Queue.Queue()
		self.writeplugin = writeplugin
		self.log = log

	def start_write(self):
		self.queue.put(("start_write",))

	def end_write(self):
		self.queue.put(("end_write",))

	def account(self, timestamp, group, addr, value):
		self.queue.put(("account", timestamp, group, addr, value))

	def notice_loss(self, timestamp, group, count):
		self.queue.put(("loss", timestamp, group, count))

	def terminate(self):
		self.queue.put(("terminate",))

	def run(self):
		try:
			self.writeplugin.run(self.queue)
		except Exception, exc:
			self.log.log_err("Caught %s from plugin: %s" %
							 (type(exc).__name__, str(exc)))
			for line in traceback.format_exc(sys.exc_info()[2]).splitlines():
				self.log.log_err(line)
			os._exit(1)
		# The plugin is now finished or it died. There is no point in keeping
		# things going, so we terminate *all* threads now.
		os._exit(0)


syslog_facilities = dict(kern=syslog.LOG_KERN, user=syslog.LOG_USER,
						 mail=syslog.LOG_MAIL, daemon=syslog.LOG_DAEMON, auth=syslog.LOG_AUTH,
						 lpr=syslog.LOG_LPR, new=syslog.LOG_NEWS, uucp=syslog.LOG_UUCP,
						 cron=syslog.LOG_CRON, local0=syslog.LOG_LOCAL0,
						 local1=syslog.LOG_LOCAL1, local2=syslog.LOG_LOCAL2,
						 local3=syslog.LOG_LOCAL3, local4=syslog.LOG_LOCAL4,
						 local5=syslog.LOG_LOCAL5, local6=syslog.LOG_LOCAL6,
						 local7=syslog.LOG_LOCAL7)

config_spec = configobj.ConfigObj(("""
[main]
plugin = string(min=1)
interval = integer(min=1)
syslog_facility = option(%(syslog_facilities)s, default='daemon')
log_level = integer(min=0, max=10, default=3)
daemonize = boolean()
pidfile = string(min=0)
[groups]
[[__many__]]
kind = string(min=1)
""" % dict(syslog_facilities=", ".join(map(repr, syslog_facilities.keys()))
)).splitlines(), interpolation=False, list_values=False)


def die(log, message):
	log.log_err(message)
	sys.stderr.write(message + "\n")
	sys.exit(1)


def daemonize(log):
	rend, wend = os.pipe()
	rend = os.fdopen(rend, "r")
	wend = os.fdopen(wend, "w")
	os.chdir("/")
	devnull = os.open("/dev/null", os.O_RDWR)
	os.dup2(devnull, 0)
	os.dup2(devnull, 1)
	# Redirect stderr later, so we can use it for die.
	try:
		if os.fork() > 0:
			wend.close()
			data = rend.read()
			if data:
				sys.stderr.write(data)
				sys.exit(1)
			sys.exit(0)
	except OSError, e:
		die(log, "first fork failed")
	os.setsid()
	try:
		if os.fork() > 0:
			sys.exit(0)
	except OSError, e:
		die(log, "second fork failed")
	rend.close()
	os.dup2(devnull, 2)
	set_close_on_exec(wend)
	return wend


def main():
	if len(sys.argv) != 2:
		print("Usage: %s <configfile>" % sys.argv[0])
		sys.exit(1)

	config = configobj.ConfigObj(sys.argv[1], configspec=config_spec, file_error=True)
	for section_list, key, error in configobj.flatten_errors(config,
															 config.validate(validate.Validator())):
		raise ValueError("failed to validate %s in section %s" %
						 (key, ", ".join(section_list)))

	log = SysloggingDebugLevel("nflogipacd",
							   facility=syslog_facilities[config["main"]["syslog_facility"]],
							   log_level=config["main"]["log_level"])

	if config["main"]["daemonize"]:
		old_stderr = sys.stderr
		sys.stderr = daemonize(log)

	log.log_notice("started")
	log.log_debug("Loading plugin %s" % config["main"]["plugin"], 0)
	try:
		plugin = imp.load_source("__plugin__", config["main"]["plugin"]).plugin(config, log)
	except Exception, exc:
		msg = "Failed to load plugin %s. Error: %s" % \
			  (config["main"]["plugin"], exc)
		log.log_err(msg)
		for line in traceback.format_exc(sys.exc_info()[2]).splitlines():
			log.log_err(line)
		sys.stderr.write(msg + "\n")
		sys.exit(1)

	if "proctitle" in config["main"]:
		try:
			setproctitle(config["main"]["proctitle"])
		except ImportError:
			die(log, "setproctitle python module is not available")

	wt = WriteThread(plugin, log)
	gt = GatherThread(int(config["main"]["interval"]), wt, log)
	for group, cfg in config["groups"].items():
		gt.add_counter(int(group), cfg["kind"])

	def handle_sigterm(*_):
		log.log_notice("received SIGTERM")
		gt.terminate()

	def handle_sighup(*_):
		log.log_notice("received SIGHUP")
		gt.ping_now()

	signal.signal(signal.SIGTERM, handle_sigterm)
	signal.signal(signal.SIGHUP, handle_sighup)
	signal.signal(signal.SIGCHLD, lambda *_: gt.handle_sigchld())

	if config["main"]["pidfile"]:
		try:
			with file(config["main"]["pidfile"], "w") as pidfile:
				pidfile.write("%d\n" % os.getpid())
		except IOError, err:
			die(log, "failed to write pidfile: %r" % err)

	if config["main"]["daemonize"]:
		sys.stderr.close()  # parent terminates cleanly
		sys.stderr = old_stderr

	# Starting write thread
	wt.start()
	try:
		# Starting gather thread
		gt.run()
	finally:
		if config["main"]["pidfile"]:
			try:
				os.unlink(config["main"]["pidfile"])
			except OSError:
				pass  # ignore
		log.log_notice("gather thread stopped")
		wt.terminate()
		log.log_notice("storage thread stopped")


if __name__ == '__main__':
	main()

# vim:ts=4 sw=4
