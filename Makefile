CC = gcc
CFLAGS = -W -Wall -Wextra -pedantic -ansi
CXX = g++
CXXFLAGS = -W -Wall -Wextra -pedantic -O2 -DUSE_STANDARD_MAP
LIBS = -lnetfilter_log
BOOST_LIBS = -lboost_thread
GZIP=gzip
PREFIX ?= /usr/local
SBINDIR ?= ${PREFIX}/sbin
MANDIR ?= ${PREFIX}/share/man
LIBDIR ?= ${PREFIX}/lib

%.o:%.c
	${CC} ${CFLAGS} -c $< -o $@

%.o:%.cpp
	${CXX} ${CXXFLAGS} -c $< -o $@

%.1.gz:%.1
	${GZIP} -9 < $< > $@

all:nfnetlink_log_ctl nflogipacd nfnetlink_log_ctl.1.gz build/.build_stamp

# Yes, Python's setup tools create a directory named "build".
build/.build_stamp:nflogipac/__init__.py nflogipac/asynschedcore.py
	python not_setup.py build
	for d in build/lib*/nflogipac; do \
		echo "# This file is automatically generated." \
			> $$d/paths.py; \
		echo "nflogipacd = '${LIBDIR}/nflogipac/nflogipacd'" \
			>> $$d/paths.py; \
	done
	touch $@

clean:
	rm -f nfnetlink_log_ctl nfnetlink_log_ctl.o
	rm -f nflogipacd nflogipacd.o
	rm -f nfnetlink_log_ctl.1.gz
	python not_setup.py clean --all
	rm -Rf build

install:nfnetlink_log_ctl nflogipacd nfnetlink_log_ctl.1.gz
	install -m755 -d ${DESTDIR}${SBINDIR}
	install -m755 nfnetlink_log_ctl ${DESTDIR}${SBINDIR}/nfnetlink_log_ctl
	install -m755 -d ${DESTDIR}${LIBDIR}/nflogipac
	install -m755 nflogipacd ${DESTDIR}${LIBDIR}/nflogipac/nflogipacd
	install -m755 -d ${DESTDIR}${MANDIR}/man1
	install -m644 nfnetlink_log_ctl.1.gz \
		${DESTDIR}${MANDIR}/man1/nfnetlink_log_ctl.1.gz
	install -m755 nflogipacd.py ${DESTDIR}${SBINDIR}/nflogipacd.py
	install -m644 examples/debugplugin.py \
		${DESTDIR}${LIBDIR}/nflogipac/debugplugin.py
	install -m644 examples/mysqlplugin.py \
		${DESTDIR}${LIBDIR}/nflogipac/mysqlplugin.py
	install -m644 examples/spawnplugin.py \
		${DESTDIR}${LIBDIR}/nflogipac/spawnplugin.py
	python not_setup.py install $(if ${DESTDIR},--root=${DESTDIR}) --prefix=${PREFIX}

nfnetlink_log_ctl:nfnetlink_log_ctl.o
	${CC} ${CFLAGS} ${LIBS} $^ -o $@
nfnetlink_log_ctl.o:nfnetlink_log_ctl.c
nflogipacd:nflogipacd.o
	${CXX} ${CXXFLAGS} ${LIBS} ${BOOST_LIBS} $^ -o $@
nflogipacd.o:nflogipacd.cpp
nfnetlink_log_ctl.1.gz:nfnetlink_log_ctl.1

.PHONY: all clean install
