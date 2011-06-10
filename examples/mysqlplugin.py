import time
import MySQLdb
import MySQLdb.cursors
import os
from nflogipac.plugins import AddressFormatter
import socket

TRAFFIC_DB_START="traffic_"


class LaggyMySQLdb:
	def __init__(self, config, name, log):
		self.config = config
		self.name = name
		self.log = log
		self.dbconf = config["databases"][name]
		self.db = None
		self.cursor = None

	def connect(self):
		self.close()
		self.log.log_debug("Trying to connect to db %s." % self.name, 4)
		self.db = MySQLdb.connect(
				host=self.dbconf["host"],
				db=self.dbconf["db"],
				user=self.dbconf["user"],
				passwd=self.dbconf["password"],
				cursorclass=MySQLdb.cursors.DictCursor)
		self.cursor = self.db.cursor()
		self.log.log_debug("Connected to db %s." % self.name, 4)

	def close(self):
		if self.cursor:
			self.cursor.close()
			self.cursor = None
		if self.db:
			self.log.log_debug("Closing connection to db %s." % self.name, 5)
			self.db.close()
			self.db = None

	def reconnect(self):
		for i in range(int(self.config["main"]["reconnect_attempts"])):
			try:
				return self.connect()
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2003: # Can't connect to MySQL server on ...
					self.log.log_err("Recieved MySQLdb.OperationalError while" +
							" connecting to %s: %r" % (self.name, error))
					raise # no clue what to do
				self.log.log_warning("Connection attempt %d to db %s failed." %
						(i, self.name))
				time.sleep(int(self.config["main"]["reconnect_interval"]))
				# implicit continue
		self.log.log_error("Giving connecting to db %s." % self.name)
		raise MySQLdb.OperationalError(2003)

	def query(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@rtype: list
		@raises MySQLdb.OperationalError
		"""
		for i in range(int(self.config["main"]["query_attempts"])):
			self.log.log_debug("Querying db %s with %r %r attempt %d" %
					(self.name, query, params, i), 8)
			try:
				self.cursor.execute(query, params)
				return self.cursor.fetchall()
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2006: # MySQL server has gone away
					self.log.log_err("Recieved MySQLdb.OperationalError while" +
							" querying %s for %r %r: %r" %
							(self.name, query, params, error))
					raise # no clue what to do
				self.log.log_warning(("MySQL server %s has gone away during " +
					"query %r %r attempt %d") % (self.name, query, params, i))
				self.reconnect()
				# implicit continue
		self.log.log_error("Giving up querying %s for %r %r." %
				(self.name, query, params))
		raise MySQLdb.OperationalError(2006)

	def execute(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@returns: None
		@raises MySQLdb.OperationalError
		"""
		for i in range(int(self.config["main"]["query_attempts"])):
			self.log.log_debug("Executing db %s with %r %r attempt %d" %
					(self.name, query, params, i), 8)
			try:
				self.cursor.execute(query, params)
				self.db.commit()
				return
			except MySQLdb.OperationalError, error:
				if error.args[0] != 2006: # MySQL server has gone away
					self.log.log_err("Recieved MySQLdb.OperationalError while" +
							" executing %r %r on %s: %r" %
							(query, params, self.name, error))
					raise # no clue what to do
				self.log.log_warning(("MySQL server %s has gone away during " +
						"execute %r %r attempt %d") %
						(self.name, query, params, i))
				self.reconnect()
				# implicit continue
		self.log.log_error("Giving up executing %r %r on %s." %
				(query, params, self.name))
		raise MySQLdb.OperationalError(2006)

class backend:
	def __init__(self, config, trafficdb, useriddb=None):
		self.config = config
		self.db = trafficdb
		self.groups = dict((int(key), value) for key, value
				in config["groups"].items())
		self.current_tables = {}
		self.useriddb = useriddb
		if all("userid" not in groupconf["insert_params"] \
					for groupconf in self.groups.values()):
			self.useriddb = None

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
		query = "%s;" % (self.config["main"]["userid_query"]
				.replace("?", "%s"))
		parammap = dict(group=group, address=addr)
		params = self.config["main"]["userid_query_params"]
		params = list(map(parammap.__getitem__, params))
		if self.useriddb is not None:
			rows = self.useriddb.query(query, params)
		else:
			rows = self.db.query(query, params)
		try:
			return rows[0]["userid"]
		except IndexError: # no rows returned
			return None # results in a NULL value

	def start_write(self):
		self.db.reconnect()
		if self.useriddb is not None:
			self.useriddb.reconnect()

	def account(self, group, addr, value):
		self.create_current_table(group)
		query = "INSERT INTO %s %s;" % (self.current_tables[group],self.groups[group]["insert"].replace("?", "%s"))
		parammap = dict(pid=os.getpid(), hostname=socket.gethostname(),
				address=addr, value=value)
		params = self.groups[group]["insert_params"]
		if "userid" in params:
			parammap["userid"] = self.lookup_userid(group, addr)
		params = list(map(parammap.__getitem__, params))

		self.db.execute(query, params)

	def end_write(self):
		if self.useriddb is not None:
			self.useriddb.close()
		self.db.close()

class plugin:
	def __init__(self, config, log):
		self.log = log
		self.queue_size_warn = int(config["main"]["queue_size_warn"])
		self.queue_age_warn = int(config["main"]["queue_age_warn"])
		self.formatter = AddressFormatter(config)
		self.backends = []

		employ_userid = any("userid" in groupconf["insert_params"]
				for groupconf in config["groups"].items())
		if "userid_query" not in config["main"] and employ_userid:
			log.log_err("Some inserts statements employ userid, but the main " +
				"section is lacking a userid_query.")
			raise ValueError("userid_query missing in main config section")
		elif "userid_query" in config["main"] and not employ_userid:
			log.log_warning("The main config sections has an unused " +
					"userid_query.")

		for dbname in config["databases"]:
			if dbname.startswith(TRAFFIC_DB_START):
				trafficdb = LaggyMySQLdb(config, dbname, log)
				log.log_debug("Found database %s for traffic information" %
						dbname, 3)
				useriddbname = "userid_%s" % dbname[len(TRAFFIC_DB_START):]
				useriddb = None
				if employ_userid and useriddbname in config["database"]:
					useriddb = LaggyMySQLdb(config, useriddbname, log)
					log.log_debug("Found database for userid information")
				elif config["main"].has_key("userid_query"):
					log.log_notice(("Not using any userid database since no " +
							"database definition %s could be found") %
							useriddbname)
				else:
					log.log_debug("Not using any userid database", 3)
						
				self.backends.append(backend(config, trafficdb, useriddb))

	def run(self, queue):
		while True:
			qsize = queue.qsize()
			if qsize > self.queue_size_warn:
				self.log.log_warning("queue contains at least %d entries" %
						qsize)
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
					self.log.log_warning("processing of queue lacks behind " +
						"for at least %d seconds" % queue_age)
				for backend in self.backends:
					backend.account(group, self.formatter(group, addr), value)
			elif entry[0] == "end_write":
				for backend in self.backends:
					backend.end_write()
# vim:ts=4 sw=4
