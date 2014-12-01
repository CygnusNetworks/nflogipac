#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Syslogging class using Python syslog module"""

import inspect
import os
import syslog
import sys

class Syslogging(object):
	"""Syslogging class providing wrapper functions for logging priorites. Should not be used directly. See classes below"""
	def __init__(self,filename=None,facility=syslog.LOG_LOCAL0,quiet=True):
		"""Initializes a new Syslogging function using a given facility. A filename can be specified, which is used in syslogging to define a prefix for the logging program
		A facility can be specified. If quiet is set to False (default to True) and no Python optimizing is done, data will be put out to std output
		A sourcecode position will be added to the log output including line numbers and python objects.
		Using enable_full_trace a complete trace will be given. Without just the last so called frame will be used.
		@param filename: A Syslog prefix (given to syslog.openlog)
		@type filename: string
		@param facility: Syslog facility. Defaults to syslog.LOG_LOCAL0
		@type facility: class
		@param quiet: Outputs log to standard output if set to False and no Python optimization is done
		@type quiet: boolean
		"""
		self.facility=facility
		self.filename=filename
		self.quiet=quiet
		self.full_trace = False

	def enable_full_trace(self):
		"""Enables full trace of function calls in log output"""
		self.full_trace = True

	def disable_full_trace(self):
		"""Disables full trace of function calls in log output"""
		self.full_trace = False

	def log_output(self,prefix,message):
		"""Outputs to stdout log message including a prefix
		@param prefix: a prefix set for the log message seperated by space from message
		@type prefix: string
		@param message: A log message
		@type message: string
		"""
		sys.stdout.write("%s %s\n" % (prefix, message))

	def log_generic(self,level,message):
		"""Generic logging function used by all other logging functions
		@param level: a syslog priority as defined by syslog Python module
		@type level: integer
		@param message: A message to be logged
		@type message: string
		"""
		syslog.openlog(self.filename,syslog.LOG_PID,self.facility)
		calling_prefix=""
		outer=inspect.getouterframes(inspect.currentframe())
		this_filename=os.path.basename(outer[0][1])
		outer.reverse()
		for elem in outer:
			if os.path.basename(elem[1])!=this_filename:
				if calling_prefix!="":
					calling_prefix+="#"
				calling_prefix+=os.path.basename(elem[1])+":"+str(elem[2])
				last_prefix=os.path.basename(elem[1])+":"+str(elem[2])
				last_function=elem[3]

		if self.full_trace:
			if last_function!="<module>":
				calling_prefix+="/"+last_function
		else:
			if last_function!="<module>":
				calling_prefix=last_prefix+"/"+last_function
			else:
				calling_prefix=last_prefix
		message=calling_prefix+"###"+message

		if level==syslog.LOG_ERR:
			if __debug__ and not self.quiet:
				self.log_output("ERR", message)
		elif level==syslog.LOG_WARNING:
			if __debug__ and self.quiet==False:
				self.log_output("WARNING",message)
		elif level==syslog.LOG_INFO:
			if __debug__ and self.quiet==False:
				self.log_output("INFO",message)
		elif level==syslog.LOG_DEBUG:
			if (__debug__) and (self.quiet==False):
				self.log_output("DEBUG",message)
		else:
			if (__debug__) and (self.quiet==False):
				self.log_output("UNKNOWN",message)
		syslog.syslog(level,message)

	def log_error(self,message):
		"""Logs a error message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_ERR,message)

	def log_err(self,message):
		"""Logs a error message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_ERR,message)

	def log_warning(self,message):
		"""Logs a warning message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_WARNING,message)

	def log_warn(self,message):
		"""Logs a warning message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_WARNING,message)

	def log_notice(self, message):
		"""Logs a notice message
		@param message: Message to be logged
		@type message: str
		"""
		self.log_generic(syslog.LOG_NOTICE, message)

	def log_info(self,message):
		"""Logs a info message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_INFO,message)

	def log_debug(self,message):
		"""Logs a debug message
		@param message: Message to be logged
		@type message: string
		"""
		self.log_generic(syslog.LOG_DEBUG,message)

class SysloggingDebugLevel(Syslogging):
	"""Class for Syslogging extending the base class and introducing a debug level function
	A debug level can be set. Messages are only logged if the given debug level in the log_debug function parameter exceeds the currently set log_level
	"""
	def __init__(self,filename,facility=syslog.LOG_LOCAL0,quiet=True,log_level=0):
		"""Constructor calling Syslogging init function and in addition introduces parameter log_level which is set to 0 as default
		@param filename: A Syslog prefix (given to syslog.openlog)
		@type filename: string
		@param facility: Syslog facility. Defaults to syslog.LOG_LOCAL0
		@type facility: class
		@param quiet: Outputs log to standard output if set to False and no Python optimization is done
		@type quiet: boolean
		@param log_level: Integer value setting the log level
		@type log_level: integer
		"""
		Syslogging.__init__(self, filename, facility=facility, quiet=quiet)
		self.log_level = log_level
		self.log_debug(filename+" started and SysloggingDebugLevel initialized")

	def set_debug_level(self,log_level):
		"""Sets a new debug level to value of log_level
		@param log_level: New log level to be set
		@type log_level: integer
		"""
		self.log_level=log_level

	def log_debug(self,message,level=0):
		"""Log function which logs a message if the given level is equal or higher the current debug log level
		@param message: A message to be logge
		@type message: string
		@param level: Log level of message
		@type level: integer
		"""
		if level<=self.log_level:
			Syslogging.log_debug(self, message)

# vim:ts=4 sw=4
