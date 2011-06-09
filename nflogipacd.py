#!/usr/bin/env python

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

try:
	from nflogipac.paths import nflogipacd as nflogipacd_path
except ImportError: # running from source directory
	nflogipacd_path = "./nflogipacd"

class FatalError(Exception):
	"""Something very bad happend leading to program abort with a message."""

def create_counter(group, kind):
	"""
	@type group: int
	@type kind: str
	@rtype: (int, socket)
	@returns: (pid, stdin_and_stdout)
	"""
	parentsock, childsock = socket.socketpair() # for communication
	parentpipe, childpipe = os.pipe() # for startup
	pid = os.fork()
	if 0 == pid: # child
		try:
			parentsock.close()
			os.close(parentpipe)
			# close signals
			pipeflags = fcntl.fcntl(childpipe, fcntl.F_GETFD)
			fcntl.fcntl(childpipe, fcntl.F_SETFD, pipeflags | fcntl.FD_CLOEXEC)
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
	def __init__(self, pinginterval, wt):
		"""
		@type pinginterval: int
		@type wt: WriteThread
		"""
		threading.Thread.__init__(self)
		self.wt = wt
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
			syslog.syslog(syslog.LOG_DEBUG, "received end packet form all counters")
			self.wt.end_write()
		if self.terminating:
			self.counters.pop(group).close()

	def periodically(self):
		syslog.syslog(syslog.LOG_DEBUG, "querying counters")
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
				syslog.syslog(syslog.LOG_NOTICE, ("child pid:%d group:%d " +
						"terminated") % (pid, group))
			else:
				syslog.syslog(syslog.LOG_ERR, ("child pid:%d group:%d " +
						"unexpectedly died") % (pid, group))
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
				if err.args[0] == errno.ECHILD: # suppress ECHILD
					return
				raise
			if pid == 0:
				return
			if self.handle_child_death(pid):
				self.terminate()

class WriteThread(threading.Thread):
	def __init__(self, writeplugin):
		threading.Thread.__init__(self)
		self.queue = Queue.Queue()
		self.writeplugin = writeplugin

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
			syslog.syslog(syslog.LOG_ERR, "Caught %s from plugin: %s" %
					(type(exc).__name__, str(exc)))
			for line in traceback.format_exc(sys.exc_info()[2]).splitlines():
				syslog.syslog(syslog.LOG_ERR, line)
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
[groups]
[[__many__]]
kind = string(min=1)
""" % dict(syslog_facilities=", ".join(map(repr, syslog_facilities.keys()))
	)).splitlines(), interpolation=False, list_values=False)

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <configfile>" % sys.argv[0])
		sys.exit(1)

	config = configobj.ConfigObj(sys.argv[1], configspec=config_spec,file_error=True)
	for section_list, key, error in configobj.flatten_errors(config,
			config.validate(validate.Validator())):
		raise ValueError("failed to validate %s in section %s" %
				(key, ", ".join(section_list)))

	syslog.openlog("nflogipacd", syslog.LOG_PID,syslog_facilities[config["main"]["syslog_facility"]])
	syslog.syslog(syslog.LOG_NOTICE, "started")
	syslog.syslog(syslog.LOG_DEBUG, "Loading plugin %s" % config["main"]["plugin"])
	try:
		plugin = imp.load_source("__plugin__",config["main"]["plugin"]).plugin(config)
	except Exception, msg:
		syslog.syslog(syslog.LOG_ERR, "Failed to load plugin %s. Error: %s" % (config["main"]["plugin"],msg))
		sys.exit(1)
		
	wt = WriteThread(plugin)
	gt = GatherThread(int(config["main"]["interval"]), wt)
	for group, cfg in config["groups"].items():
		gt.add_counter(int(group), cfg["kind"])

	def handle_sigterm(*_):
		syslog.syslog(syslog.LOG_NOTICE, "recevied SIGTERM")
		gt.terminate()
	def handle_sighup(*_):
		syslog.syslog(syslog.LOG_NOTICE, "received SIGHUP")
		gt.ping_now()
	signal.signal(signal.SIGTERM, handle_sigterm)
	signal.signal(signal.SIGHUP, handle_sighup)
	signal.signal(signal.SIGCHLD, lambda *_: gt.handle_sigchld())

	# Starting write thread
	wt.start()
	try:
		# Starting gather thread
		gt.run()
	finally:
		syslog.syslog(syslog.LOG_NOTICE, "gather thread stopped")
		wt.terminate()
		syslog.syslog(syslog.LOG_NOTICE, "storage thread stopped")

if __name__ == '__main__':
	main()

# vim:ts=4 sw=4
