from nflogipac import AddressFormatter

class plugin:
	def __init__(self, config):
		self.config = config
		self.formatter = AddressFormatter(config)

	def run(self, queue):
		while True:
			entry = queue.get()
			if entry[0] == "terminate":
				return
			if entry[0] == "account":
				timestamp, group, addr, value = entry[1:]
				addr = self.formatter(group, addr)
				print("accounting %d bytes for address %s on group %d" %
						(value, addr, group))
