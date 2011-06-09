import time
import MySQLdb
import MySQLdb.cursors
import os
from nflogipac.plugins import AddressFormatter
import syslog
import socket

class LaggyMySQLdb:
	def __init__(self, dbconf, config):
		self.dbconf = dbconf
		self.config = config
		self.db = None
		self.cursor = None

	def connect(self):
		self.close()
		self.db = MySQLdb.connect(
				host=self.dbconf["host"],
				db=self.dbconf["db"],
				user=self.dbconf["user"],
				passwd=self.dbconf["password"],
				cursorclass=MySQLdb.cursors.DictCursor)
		self.cursor = self.db.cursor()

	def close(self):
		if self.cursor:
			self.cursor.close()
			self.cursor = None
		if self.db:
			self.db.close()
			self.db = None

	def reconnect(self):
		for _ in range(int(self.config["main"]["reconnect_attempts"])):
			try:
				return self.connect()
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2003: # Can't connect to MySQL server on ...
					raise # no clue what to do
				time.sleep(int(self.config["main"]["reconnect_interval"]))
				# implicit continue
		raise MySQLdb.OperationalError(2003)

	def query(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@rtype: list
		@raises MySQLdb.OperationalError
		"""
		for _ in range(int(self.config["main"]["query_attempts"])):
			try:
				self.cursor.execute(query, params)
				return self.cursor.fetchall()
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2006: # MySQL server has gone away
					raise # no clue what to do
				self.reconnect()
				# implicit continue
		raise MySQLdb.OperationalError(2006)

	def execute(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@returns: None
		@raises MySQLdb.OperationalError
		"""
		for _ in range(int(self.config["main"]["query_attempts"])):
			try:
				self.cursor.execute(query, params)
				self.db.commit()
				return
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2006: # MySQL server has gone away
					raise # no clue what to do
				self.reconnect()
				# implicit continue
		raise MySQLdb.OperationalError(2006)

class backend:
	def __init__(self, dbconf, config):
		self.config = config
		self.db = LaggyMySQLdb(dbconf, config)
		self.groups = dict((int(key), value) for key, value
				in config["groups"].items())
		self.current_tables = {}

	def create_current_table(self, group):
		table_name = self.groups[group]["table_prefix"] + \
				time.strftime(self.groups[group]["table_strftime"],
						time.gmtime())
		if table_name == self.current_tables.get(group):
			return
		query = "CREATE TABLE IF NOT EXISTS %s %s;" % (table_name,
				self.groups[group]["create_table"])
		self.db.execute(query, ())
		self.current_tables[group] = table_name

	def lookup_userid(self, group, addr):
		query = "SELECT %s;" % (self.config["main"]["userid_query"]
				.replace("?", "%s"))
		parammap = dict(group=group, address=addr)
		params = self.config["main"]["userid_query_params"]
		params = list(map(parammap.__getitem__, params))
		rows = self.db.query(query, params)
		try:
			return rows[0]["userid"]
		except IndexError: # no rows returned
			return None # results in a NULL value

	def start_write(self):
		self.db.connect()

	def account(self, group, addr, value):
		self.create_current_table(group)
		query = "INSERT INTO %s %s;" % (self.current_tables[group],
				self.groups[group]["insert"].replace("?", "%s"))
		parammap = dict(pid=os.getpid(), hostname=socket.gethostname(),
				address=addr, value=value)
		params = self.groups[group]["insert_params"]
		if "userid" in params:
			parammap["userid"] = self.lookup_userid(group, addr)
		params = list(map(parammap.__getitem__, params))
		self.db.execute(query, params)

	def end_write(self):
		self.db.close()

class plugin:
	def __init__(self, config):
		self.queue_size_warn = int(config["main"]["queue_size_warn"])
		self.queue_age_warn = int(config["main"]["queue_age_warn"])
		self.formatter = AddressFormatter(config)
		self.backends = []
		for dbconf in config["databases"].values():
			self.backends.append(backend(dbconf, config))

	def run(self, queue):
		while True:
			qsize = queue.qsize()
			if qsize > self.queue_size_warn:
				syslog.syslog(syslog.LOG_WARNING, ("queue contains at least " +
						"%d entries") % qsize)
			entry = queue.get()
			if entry[0] == "terminate":
				return
			elif entry[0] == "start_write":
				for backend in self.backends:
					backend.start_write()
			elif entry[0] == "account":
				timestamp, group, addr, value = entry[1:]
				queue_age = time.time() - timestamp
				if queue_age > self.queue_age_warn:
					syslog.syslog(syslog.LOG_WARNING, "processing of queue " +
							"lacks behind for at least %d seconds" % queue_age)
				for backend in self.backends:
					backend.account(group, self.formatter(group, addr), value)
			elif entry[0] == "end_write":
				for backend in self.backends:
					backend.end_write()

# vim:ts=4 sw=4
