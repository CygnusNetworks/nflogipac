#!/usr/bin/env python

import struct
import time
import os
import asyncore
import socket
import sched
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

def create_counter(group, kind, exe):
	"""
	@type group: int
	@type kind: str
	@type exe: str
	@rtype: (int, socket)
	@returns: (pid, stdin_and_stdout)
	"""
	parentsock, childsock = socket.socketpair()
	pid = os.fork()
	if 0 == pid: # child
		parentsock.close()
		os.close(0)
		os.close(1)
		os.dup2(childsock.fileno(), 0)
		os.dup2(childsock.fileno(), 1)
		os.execv(exe, [exe, "%d" % group, kind])
		sys.exit(1)

	# parent
	childsock.close()
	return pid, parentsock

class Counter(asyncore.dispatcher):
	def __init__(self, group, kind, exe, map=None):
		"""
		@type group: int
		@type kind: str
		@type exe: str
		"""
		self.group = group
		self.kind = kind
		self.pid, counter_sock = create_counter(group, kind, exe)
		asyncore.dispatcher.__init__(self, sock=counter_sock, map=map)
		self.requesting_data = False
		self.buf = ""

	def request_data(self):
		self.requesting_data = True

	def writable(self):
		return self.requesting_data

	def handle_write(self):
		if self.send("x"):
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
			self.handle_cmd_update(addr, value)
		elif command == 2:
			if content != "":
				self.close()
				return
			self.handle_cmd_end()
		else:
			self.close()

	def handle_cmd_update(self, addr, value):
		"""
		@type addr: str
		@type value: int or long
		"""
		raise NotImplementedError

	def handle_cmd_end(self):
		raise NotImplementedError

class DebugCounter(Counter):
	def __init__(self, *args, **kwargs):
		Counter.__init__(self, *args, **kwargs)
		self.pending = collections.defaultdict(long)

	def handle_cmd_update(self, addr, value):
		self.pending[addr] += value
		print("received update for group %d addr %s value %d" %
				(self.group, addr.encode("hex"), value))

	def handle_cmd_end(self):
		print("end %r" % (self.pending,))

class asynschedcore(sched.scheduler):
	"""Combine sched.scheduler and asyncore.loop."""
	# On receiving a signal asyncore kindly restarts select. However the signal
	# handler might change the scheduler instance. This tunable determines the
	# maximum time in seconds to spend in asycore.loop before reexamining the
	# scheduler.
	maxloop = 30
	def __init__(self, map=None):
		sched.scheduler.__init__(self, time.time, self._delay)
		if map is None:
			self._asynmap = asyncore.socket_map
		else:
			self._asynmap = map
		self._abort_delay = False

	def _maybe_abort_delay(self):
		if not self._abort_delay:
			return False
		# Returning from this function causes the next event to be executed, so
		# it might be executed too early. This can be avoided by modifying the
		# head of the queue. Also note that enterabs sets _abort_delay to True.
		self.enterabs(0, 0, lambda:None, ())
		self._abort_delay = False
		return True

	def _delay(self, timeout):
		if self._maybe_abort_delay():
			return
		if 0 == timeout:
			# Should we support this hack, too?
			# asyncore.loop(0, map=self._asynmap, count=1)
			return
		now = time.time()
		finish = now + timeout
		while now < finish and self._asynmap:
			asyncore.loop(min(finish - now, self.maxloop), map=self._asynmap,
					count=1)
			if self._maybe_abort_delay():
				return
			now = time.time()
		if now < finish:
			time.sleep(finish - now)

	def enterabs(self, abstime, priority, action, argument):
		# We might insert an event before the currently next event.
		self._abort_delay = True
		return sched.scheduler.enterabs(self, abstime, priority, action,
				argument)

	# Overwriting enter is not necessary, because it is implemented using enter.

	def cancel(self, event):
		# We might cancel the next event.
		self._abort_delay = True
		return sched.scheduler.cancel(self, event)

	def run(self):
		"""Runs as long as either an event is scheduled or there are
		sockets in the map."""
		while True:
			if not self.empty():
				sched.scheduler.run(self)
			elif self._asynmap:
				asyncore.loop(self.maxloop, map=self._asynmap, count=1)
			else:
				break

class ReportingCounter(Counter):
	def __init__(self, group, kind, exe, writefunc, map=None):
		"""
		@type group: int
		@type kind: str
		@type writefunc: (int, str, int) -> None
		@param writefunc: is a function taking a group, a binary IP (4 or 6)
				address and a byte count. It must not block or fail.
		"""
		Counter.__init__(self, group, kind, exe, map)
		self.writefunc = writefunc
		self.close_on_end = False

	def schedule_terminate(self):
		self.close_on_end = True

	def handle_cmd_update(self, addr, value):
		self.writefunc(self.group, addr, value)

	def handle_cmd_end(self):
		if self.close_on_end:
			self.close()

class GatherThread(threading.Thread):
	def __init__(self, pinginterval, exe, writefunc):
		"""
		@type pinginterval: int
		@type writefunc: (int, str, int) -> None
		@param writefunc: is a function taking a group, a binary IP (4 or 6)
				address and a byte count. It must not block or fail.
		"""
		threading.Thread.__init__(self)
		self.pinginterval = pinginterval
		self.exe = exe
		self.writefunc = writefunc
		self.asynmap = {}
		self.asc = asynschedcore(self.asynmap)
		self.counters = []
		self.nextping = None

	def add_counter(self, group, kind):
		"""
		@type group: int
		@type kind: str
		"""
		self.counters.append(
				ReportingCounter(group, kind, self.exe, self.writefunc,
					self.asynmap))

	def schedule_ping(self):
		if self.asynmap and self.nextping is None:
			self.nextping = self.asc.enter(self.pinginterval, 0,
					self.ping_counters, ())

	def ping_counters(self):
		self.nextping = None
		for counter in self.counters:
			counter.request_data()
		self.schedule_ping()

	def run(self):
		self.schedule_ping()
		self.asc.run()

	def ping_now(self):
		if self.nextping is not None:
			self.asc.cancel(self.nextping)
		self.ping_counters()

	def terminate(self):
		if self.nextping is not None:
			self.asc.cancel(self.nextping)
			self.nextping = None

		for counter in self.counters:
			counter.request_data()
			counter.schedule_terminate()

class WriteThread(threading.Thread):
	def __init__(self, writeplugin):
		threading.Thread.__init__(self)
		self.queue = Queue.Queue()
		self.writeplugin = writeplugin

	def writefunc(self, group, addr, value):
		self.queue.put((group, addr, value))

	def terminate(self):
		self.queue.put(None)

	def run(self):
		while True:
			entry = self.queue.get()
			if entry is None:
				break
			group, addr, value = entry
			try:
				self.writeplugin(group, addr, value)
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
exe = string(min=1)
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
	gt = GatherThread(int(config["main"]["interval"]), config["main"]["exe"],
		wt.writefunc)
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
