import time
import MySQLdb
import MySQLdb.cursors
import os
from nflogipac import AddressFormatter

class backend:
	def __init__(self, dbconf, config):
		self.dbconf = dbconf
		self.config = config
		self.db = None
		self.cursor = None
		self.groups = dict((int(key), value) for key, value
				in config["groups"].items())
		self.current_tables = {}
		self.do_connect()

	def do_connect(self):
		self.do_close()
		self.db = MySQLdb.connect(
				host=self.dbconf["host"],
				db=self.dbconf["db"],
				user=self.dbconf["user"],
				passwd=self.dbconf["password"],
				cursorclass=MySQLdb.cursors.DictCursor)
		self.cursor = self.db.cursor()

	def do_close(self):
		if self.cursor:
			self.cursor.close()
			self.cursor = None
		if self.db:
			self.db.close()
			self.db = None

	def create_current_table(self, group):
		table_name = "%s%s" % (self.groups[group]["table_prefix"],
				time.strftime("%g_%m", time.gmtime()))
		if table_name == self.current_tables.get(group):
			return
		query = "CREATE TABLE IF NOT EXISTS %s %s;" % (table_name,
				self.groups[group]["create_table"])
		self.cursor.execute(query, ())
		self.current_tables[group] = table_name

	def lookup_userid(self, group, addr):
		query = "SELECT %s;" % (self.config["main"]["userid_query"]
				.replace("?", "%s"))
		parammap = dict(group=group, address=addr)
		params = self.config["main"]["userid_query_params"]
		params = list(map(parammap.__getitem__, params))
		self.cursor.execute(query, params)
		rows = self.cursor.fetchall()
		return rows[0]["userid"]

	def __call__(self, group, addr, value):
		self.create_current_table(group)
		query = "INSERT INTO %s %s;" % (self.current_tables[group],
				self.groups[group]["insert"].replace("?", "%s"))
		parammap = dict(pid=os.getpid(), address=addr, value=value)
		params = self.groups[group]["insert_params"]
		if "userid" in params:
			parammap["userid"] = self.lookup_userid(group, addr)
		params = list(map(parammap.__getitem__, params))
		self.cursor.execute(query, params)
		self.db.commit()

class plugin:
	def __init__(self, config):
		self.formatter = AddressFormatter(config)
		self.backends = []
		for dbconf in config["databases"].values():
			self.backends.append(backend(dbconf, config))

	def account(self, timestamp, group, addr, value):
		for backend in self.backends:
			backend(group, self.formatter(group, addr), value)
