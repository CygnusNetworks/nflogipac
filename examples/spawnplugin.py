"""
Spawn a process for each report and feed data on stdin in a '/' delimited ascii
format. The fields of input lines are timestamp, group, address and value. The
daemon terminates if the child exits with a non-zero status. The main section
of the configuration file must contain a key cmdline which is passed to the
shell for spawning the process.
"""

import subprocess
from nflogipac import AddressFormatter

class plugin:
	def __init__(self, config):
		self.cmdline = config["main"]["cmdline"]
		self.formatter = AddressFormatter(config)
		self.child = None

	def run(self, queue):
		while True:
			entry = queue.get()
			if entry[0] == "terminate":
				return
			elif entry[0] == "start_write":
				self.start_write()
			elif entry[0] == "account":
				timestamp, group, addr, value = entry[1:]
				addr = self.formatter(group, addr)
				self.account(timestamp, group, addr, value)
			elif entry[0] == "end_write":
				self.end_write()

	def start_write(self):
		assert self.child is None
		self.child = subprocess.Popen(self.cmdline, shell=True,
				stdin=subprocess.PIPE, close_fds=True)

	def account(self, timestamp, group, addr, value):
		assert self.child is not None
		self.child.stdin.write("%d/%d/%s/%d\n" %
				(timestamp, group, addr, value))

	def end_write(self):
		assert self.child is not None
		self.child.stdin.close()
		retcode = self.child.wait()
		self.child = None
		if retcode != 0:
			raise ValueError("child returned non-zero")
