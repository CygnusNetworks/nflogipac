#
# -*- encoding: utf8 -*-
#
# Copyright (C) 2011-2012 Cygnus Networks GmbH <info@cygnusnetworks.de>
# Copyright (C) 2011      Daniel Meißner <dm@3st.be>
#
# License: GPL3
#
# imported from git://github.com/meise/nflogipac-postgresql-plugin.git
#

import time
import psycopg2
import os
from nflogipac.plugins import AddressFormatter
import socket

# prefix of all active databases in the configuration
TRAFFIC_DB_START = "traffic_"


class LaggyPostgreSQLdb:
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
		self.db = psycopg2.connect(
			host=self.dbconf["host"],
			database=self.dbconf["db"],
			user=self.dbconf["user"],
			password=self.dbconf["password"])
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
			except psycopg2.OperationalError, error:
				if error.args[0] != "08001":  # Can't connect to PostgreSQL server on ...
					self.log.log_err("Recieved psycopg2.OperationalError while" +
									 " connecting to %s: %r" % (self.name, error))
					raise  # no clue what to do
				self.log.log_warning("Connection attempt %d to db %s failed." %
									 (i, self.name))
				time.sleep(int(self.config["main"]["reconnect_interval"]))
			# implicit continue
		self.log.log_error("Giving connecting to db %s." % self.name)
		raise psycopg2.OperationalError("08001")

	def query(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@rtype: list
		@raises psycopg2.OperationalError
		"""
		for i in range(int(self.config["main"]["query_attempts"])):
			self.log.log_debug("Querying db %s with %r %r attempt %d" %
							   (self.name, query, params, i), 8)
			try:
				self.cursor.execute(query, params)
				return self.cursor.fetchall()
			except psycopg2.OperationalError, error:
				if error.args[0] != "08007":  # PostgreSQL server has gone away
					self.log.log_err("Recieved psycopg2.OperationalError while" +
									 " querying %s for %r %r: %r" %
									 (self.name, query, params, error))
					raise  # no clue what to do
				self.log.log_warning(("PostgreSQL server %s has gone away during " +
									  "query %r %r attempt %d") % (self.name, query, params, i))
				self.reconnect()
			# implicit continue
		self.log.log_error("Giving up querying %s for %r %r." %
						   (self.name, query, params))
		raise psycopg2.OperationalError("08007")

	def execute(self, query, params):
		"""
		@type query: str
		@type params: tuple
		@returns: None
		@raises psycopg2.OperationalError
		"""
		for i in range(int(self.config["main"]["query_attempts"])):
			self.log.log_debug("Executing db %s with %r %r attempt %d" %
							   (self.name, query, params, i), 8)
			try:
				self.cursor.execute(query, params)
				self.db.commit()
				return
			except psycopg2.OperationalError, error:
				if error.args[0] != "08007":  # PostgreSQL server has gone away
					self.log.log_err("Recieved psycopg2.OperationalError while" +
									 " executing %r %r on %s: %r" %
									 (query, params, self.name, error))
					raise  # no clue what to do
				self.log.log_warning(("PostgreSQL server %s has gone away during " +
									  "execute %r %r attempt %d") %
									 (self.name, query, params, i))
				self.reconnect()
			# implicit continue
		self.log.log_error("Giving up executing %r %r on %s." %
						   (query, params, self.name))
		raise psycopg2.OperationalError("08007")


class backend:
	def __init__(self, config, trafficdb):
		self.config = config
		self.db = trafficdb
		self.groups = dict((int(key), value) for key, value
						   in config["groups"].items())
		self.current_tables = {}

	def create_current_table(self, group):
		table_name = self.groups[group]["table_name"]
		if table_name == self.current_tables.get(group):
			return

		query = "create or replace function update_the_db() returns void as \
			$$ \
			begin \
			if not exists(select * from information_schema.tables \
				where \
					table_catalog = CURRENT_CATALOG and table_schema = CURRENT_SCHEMA \
					and table_name = '%s') then \
				CREATE TABLE %s %s; CREATE INDEX %s_IP on %s (IP); CREATE INDEX %s_ipdir ON %s (IP,direction); \
			    end if; \
			end; \
			$$ \
			language 'plpgsql'; \
			select update_the_db(); \
			drop function update_the_db();" % (table_name, table_name, self.groups[group]["create_table"], table_name, table_name, table_name, table_name)
		self.db.execute(query, ())
		self.current_tables[group] = table_name

	def start_write(self):
		self.db.reconnect()

	def account(self, group, addr, value):
		self.create_current_table(group)
		query = "INSERT INTO %s %s;" % (self.current_tables[group], self.groups[group]["insert"].replace("?", "%s"))
		parammap = dict(pid=os.getpid(), hostname=socket.gethostname(),
						address=addr, value=value)
		params = self.groups[group]["insert_params"]

		params = list(map(parammap.__getitem__, params))

		self.db.execute(query, params)

	def end_write(self):
		self.db.close()


class plugin:
	def __init__(self, config, log):
		self.log = log
		self.queue_size_warn = int(config["main"]["queue_size_warn"])
		self.queue_age_warn = int(config["main"]["queue_age_warn"])
		self.formatter = AddressFormatter(config)
		self.backends = []

		for dbname in config["databases"]:
			if dbname.startswith(TRAFFIC_DB_START):
				trafficdb = LaggyPostgreSQLdb(config, dbname, log)
				log.log_debug("Found database %s for traffic information" %
							  dbname, 3)
				self.backends.append(backend(config, trafficdb))

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
			elif entry[0] == "loss":
				timestamp, group, count = entry[2:]
				age = time.time() - timestamp
				self.log.log_warning(("collector missed at least %d packets " +
									  "in group %d observed %ds ago") % (count, group, age))
			elif entry[0] == "end_write":
				for backend in self.backends:
					backend.end_write()

# vim:ts=4 sw=4
