import socket

class AddressFormatter:
	kindtofamily = dict(
			ipv4src=socket.AF_INET, ipv4dst=socket.AF_INET,
			ipv6src=socket.AF_INET6, ipv6dst=socket.AF_INET6)

	def __init__(self, config):
		self.groupmap = {}
		for group, gconfig in config["groups"].items():
			kind = gconfig["kind"].split('/', 1)[0]
			if not group.isdigit():
				raise ValueError("non-numeric subsection in groups: %s" % group)
			if kind not in self.kindtofamily:
				raise ValueError("unknown kind: %s" % kind)
			self.groupmap[int(group)] = self.kindtofamily[kind]

	def __call__(self, group, binaryaddress):
		"""
		@type group: int
		@type binaryaddress: str
		@rtype: str
		@raises KeyErrror: if the group is not configured
		@raises ValueError: if the binary address has a wrong length
		"""
		return socket.inet_ntop(self.groupmap[group], binaryaddress)

class SimplePlugin:
	"""A possible base class for simple plugins. It translates events to
	calling "handle_..." methods if present."""
	def __init__(self, config):
		pass

	def run(self, queue):
		cmd = None
		while cmd != "handle_terminate":
			entry = queue.get()
			cmd = "handle_%s" % (entry[0],)
			params = entry[1:]

			if hasattr(self, cmd):
				getattr(self, cmd)(*params)

class FormattingPlugin(SimplePlugin):
	"""Implements handle_account for SimplePlugin by calling
	handle_formatted_account with an ascii representation of the address."""
	def __init__(self, config):
		SimplePlugin.__init__(self, config)
		self.formatter = AddressFormatter(config)

	def handle_formatted_account(self, timestamp, group, addr, value):
		raise NotImplementedError

	def handle_account(self, timestamp, group, addr, value):
		self.handle_formatted_account(timestamp, group,
				self.formatter(group, addr), value)

# vim:ts=4 sw=4
