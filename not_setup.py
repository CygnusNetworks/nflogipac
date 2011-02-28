#!/usr/bin/python
# Even though this looks like a setup.py it is only half the story. This file
# is used by the Makefile to install the Python parts.

import distutils.core

distutils.core.setup(name='nflogipac',
	version='0.1',
	description="netfilter NFLOG based IP accounting daemon",
	long_description="""It allows IP based accounting of traffic that is matched by iptables rules. Instead of the ULOG the more recent NFLOG target is used. This allows accounting IPv6 traffic. Furthermore this software is a hybrid of C++ and Python. The performance of C++ is used to count the traffic and the flexibility of Python is used to store the accounting information in a (MySQL) database.""",
	author='Helmut Grohne',
	author_email='h.grohne@cygnusnetworks.de',
	maintainer='Torge Szczepanek',
	maintainer_email='debian@cygnusnetworks.de',
	license='GNU GPLv3',
	packages=['nflogipac'],
	classifiers=[
		"Development Status :: 2 - Pre-Alpha",
		"License :: OSI Approved :: GNU General Public License (GPL)",
		"Operating System :: POSIX :: Linux",
		"Intended Audience :: System Administrators",
		"Programming Language :: C",
		"Programming Language :: C++",
		"Programming Language :: Python :: 2",
		"Topic :: System :: Networking",
		]
	)

# vim:ts=4 sw=4
