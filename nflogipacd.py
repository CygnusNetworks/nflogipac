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
		print "we lost %d packets" % count
		# raise NotImplementedError # TODO: make overriding mandatory

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

class ReportingCounter(Counter):
	def __init__(self, group, kind, writefunc, map=None):
		"""
		@type group: int
		@type kind: str
		@type writefunc: (float, int, str, int) -> None
		@param writefunc: is a function taking a timestamp, a group, a binary
				IP (4 or 6) address and a byte count. It must not block or fail.
		"""
		Counter.__init__(self, group, kind, map)
		self.writefunc = writefunc
		self.close_on_end = False

	def schedule_terminate(self):
		self.close_on_end = True

	def handle_cmd_update(self, timestamp, addr, value):
		self.writefunc(timestamp, self.group, addr, value)

	def handle_cmd_end(self):
		if self.close_on_end:
			self.close()

class GatherThread(threading.Thread):
	def __init__(self, pinginterval, wt):
		"""
		@type pinginterval: int
		@type wt: WriteThread
		"""
		threading.Thread.__init__(self)
		self.wt = wt
		self.asynmap = {}
		self.asc = asynschedcore(self.asynmap)
		self.periodic = periodic(self.asc, pinginterval, 0, self.request_data)
		self.counters = []

	def add_counter(self, group, kind):
		"""
		@type group: int
		@type kind: str
		"""
		self.counters.append(
				ReportingCounter(group, kind, self.wt.account, self.asynmap))

	def request_data(self):
		self.wt.start_write()
		for counter in self.counters:
			counter.request_data()
		if not self.asynmap:
			self.periodic.stop()

	def run(self):
		if self.asynmap:
			self.periodic.start()
		self.asc.run()

	def ping_now(self):
		self.periodic.call_now()

	def terminate(self):
		self.periodic.stop()
		for counter in self.counters:
			counter.request_data()
			counter.schedule_terminate()

class WriteThread(threading.Thread):
	def __init__(self, writeplugin):
		threading.Thread.__init__(self)
		self.queue = Queue.Queue()
		self.writeplugin = writeplugin

	def start_write(self):
		self.queue.put(("start_write",))

	def account(self, timestamp, group, addr, value):
		self.queue.put(("account", timestamp, group, addr, value))

	def terminate(self):
		self.queue.put(("terminate",))

	def run(self):
		while True:
			entry = self.queue.get()
			if entry[0] == "terminate":
				break
			elif entry[0] == "account":
				timestamp, group, addr, value = entry[1:]
				try:
					self.writeplugin.account(timestamp, group, addr, value)
				except Exception, e:
					syslog.syslog(syslog.LOG_ERR, "Caught %s from backend: %s" %
							(type(e).__name__, str(e)))
					for line in traceback.format_exc(sys.exc_info()[2]) \
							.splitlines():
						syslog.syslog(syslog.LOG_ERR, line)

config_spec = configobj.ConfigObj("""
[main]
plugin = string(min=1)
interval = integer(min=1)
[groups]
[[__many__]]
kind = string(min=1)
""".splitlines(), interpolation=False, list_values=False)

def main():
	config = configobj.ConfigObj(sys.argv[1], configspec=config_spec)
	for section_list, key, error in configobj.flatten_errors(config,
			config.validate(validate.Validator())):
		raise ValueError("failed to validate %s in section %s" %
				(key, ", ".join(section_list)))

	plugin = imp.load_source("__plugin__",
			config["main"]["plugin"]).plugin(config)
	wt = WriteThread(plugin)
	gt = GatherThread(int(config["main"]["interval"]), wt)
	for group, cfg in config["groups"].items():
		gt.add_counter(int(group), cfg["kind"])

	def handle_sigterm(signum, frame):
		gt.terminate()
	def handle_sighup(signum, frame):
		gt.ping_now()
	signal.signal(signal.SIGTERM, handle_sigterm)
	signal.signal(signal.SIGHUP, handle_sighup)
	syslog.openlog("nflogipac", syslog.LOG_PID, syslog.LOG_DAEMON)

	wt.start()
	try:
		gt.run()
	finally:
		wt.terminate()

if __name__ == '__main__':
	main()
