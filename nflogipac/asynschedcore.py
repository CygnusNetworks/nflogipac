import asyncore
import sched
import time

class asynschedcore(sched.scheduler):
	"""Combine sched.scheduler and asyncore.loop.

	If asyncore.ExitNow is raised from anything (indirectly) called by the run
	method, the exception is passed through, because asyncore passes on this
	exception and sched passes on any exceptions.

	@type asynmap: dict
	@ivar asynmap: Is the map argument passed to asyncore.loop. It is either
			taken from the constructor or from asyncore.socket_map.
	"""
	# On receiving a signal asyncore kindly restarts select. However the signal
	# handler might change the scheduler instance. This tunable determines the
	# maximum time in seconds to spend in asycore.loop before reexamining the
	# scheduler.
	maxloop = 30
	def __init__(self, map=None):
		"""
		@type map: dict or None
		@param map: If given this map specifies the map argument passed to
				asyncore.loop. It is also exported the instance attribute
				asynmap.
		"""
		sched.scheduler.__init__(self, time.time, self._delay)
		if map is None:
			self.asynmap = asyncore.socket_map
		else:
			self.asynmap = map
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
			# asyncore.loop(0, map=self.asynmap, count=1)
			return
		now = time.time()
		finish = now + timeout
		while now < finish and self.asynmap:
			asyncore.loop(min(finish - now, self.maxloop), map=self.asynmap,
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
		sockets in the map. For further details see the documentation of
		sched.scheduler.run and asyncore.loop."""
		while True:
			if not self.empty():
				sched.scheduler.run(self)
			elif self.asynmap:
				asyncore.loop(self.maxloop, map=self.asynmap, count=1)
			else:
				break

class periodic:
	"""Set up a function for periodic invocation with a scheduler."""
	def __init__(self, schedinst, interval, priority, function, *args,
			**kwargs):
		"""
		@type schedinst: sched.scheduler
		@type interval: int or float
		@type priority: int or float
		"""
		self.schedinst = schedinst
		self.interval = interval
		self.priority = priority
		self.function = function
		self.args = args
		self.kwargs = kwargs
		self.event = None

	def start(self):
		"""Start the periodic now. Calling this method or schedule twice is an
		error unless stop is called in between."""
		self.schedule()
		self.function(*self.args, **self.kwargs)

	def schedule(self):
		"""Schedule execution of the periodic with the specified interval.
		Calling this method or start twice is an error unless stop is called in
		between."""
		if self.event is not None:
			raise ValueError("already started or scheduled")
		self.event = self.schedinst.enter(self.interval, self.priority,
				self._call_wrapper, ())

	def stop(self):
		"""Stop periodic execution no matter whether it was already stopped or
		not."""
		if self.event is not None:
			self.schedinst.cancel(self.event)
			self.event = None

	def call_now(self):
		"""Call the function now. If the periodic is scheduled the next
		invocation is rescheduled with the interval."""
		if self.event is not None:
			self.stop()
			self.start()
		else:
			self.function(*self.args, **self.kwargs)

	def _call_wrapper(self):
		assert self.event is not None
		self.event = None
		self.schedule()
		self.function(*self.args, **self.kwargs)

# vim:ts=4 sw=4
