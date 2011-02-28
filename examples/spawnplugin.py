"""
Spawn a process for each report and feed data on stdin in a '/' delimited ascii
format. The fields of input lines are timestamp, group, address and value. The
daemon terminates if the child exits with a non-zero status. The main section
of the configuration file must contain a key cmdline which is passed to the
shell for spawning the process.
"""

import subprocess
from nflogipac.plugins import FormattingPlugin

class plugin(FormattingPlugin):
	def __init__(self, config):
		FormattingPlugin.__init__(self, config)
		self.cmdline = config["main"]["cmdline"]
		self.child = None

	def handle_start_write(self):
		assert self.child is None
		self.child = subprocess.Popen(self.cmdline, shell=True,
				stdin=subprocess.PIPE, close_fds=True)

	def handle_formatted_account(self, timestamp, group, addr, value):
		assert self.child is not None
		self.child.stdin.write("%d/%d/%s/%d\n" %
				(timestamp, group, addr, value))

	def handle_end_write(self):
		assert self.child is not None
		self.child.stdin.close()
		retcode = self.child.wait()
		self.child = None
		if retcode != 0:
			raise ValueError("child returned non-zero")

# vim:ts=4 sw=4
