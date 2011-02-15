from nflogipac import AddressFormatter

class plugin:
	def __init__(self, config):
		self.config = config
		self.formatter = AddressFormatter(config)
	def account(self, timestamp, group, addr, value):
		addr = self.formatter(group, addr)
		print("accounting %d bytes for address %s on group %d" %
				(value, addr, group))
