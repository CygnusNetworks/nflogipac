import socket

class plugin:
	def __init__(self, config):
		self.config = config
		formatmap = dict(ipv4=socket.AF_INET, ipv6=socket.AF_INET6)
		self.groupmap = dict((int(key), formatmap[value["addrformat"]])
			for key, value in config["groups"].items())
	def account(self, timestamp, group, addr, value):
		addr = socket.inet_ntop(self.groupmap[group], addr)
		print("accounting %d bytes for address %s on group %d" %
				(value, addr, group))
