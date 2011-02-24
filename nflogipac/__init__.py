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

# vim:ts=4 sw=4
