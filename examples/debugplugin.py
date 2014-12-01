# -*- coding: utf-8 -*-

from nflogipac.plugins import FormattingPlugin


class plugin(FormattingPlugin):
	def __init__(self, config, log):
		FormattingPlugin.__init__(self, config)

	def handle_formatted_account(self, timestamp, group, addr, value):
		print("accounting %d bytes for address %s on group %d" %
			  (value, addr, group))

	@staticmethod
	def handle_loss(timestamp, group, count):
		print("missed at least %d packets for group %d" %
			  (count, group))

	@staticmethod
	def handle_end_write():
		print("ending write")

# vim:ts=4 sw=4
