from nflogipac.plugins import FormattingPlugin

class plugin(FormattingPlugin):
	def __init__(self, config):
		FormattingPlugin.__init__(self, config)

	def handle_formatted_account(self, timestamp, group, addr, value):
		print("accounting %d bytes for address %s on group %d" %
				(value, addr, group))

	def handle_end_write(self):
		print("ending write")

# vim:ts=4 sw=4
