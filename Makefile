CC = gcc
CFLAGS = -W -Wall -Wextra -pedantic -ansi
CXX = g++
CXXFLAGS = -W -Wall -Wextra -pedantic -O2
LIBS = -lnetfilter_log
BOOST_LIBS = -lboost_thread
GZIP=gzip
PREFIX ?= /usr/local
SBINDIR ?= ${PREFIX}/sbin
MANDIR ?= ${PREFIX}/share/man

%.o:%.c
	${CC} ${CFLAGS} -c $< -o $@

%.o:%.cpp
	${CXX} ${CXXFLAGS} -c $< -o $@

%.1.gz:%.1
	${GZIP} -9 < $< > $@

all:nfnetlink_log_ctl nflogipacd nfnetlink_log_ctl.1.gz
clean:
	rm -f nfnetlink_log_ctl nfnetlink_log_ctl.o
	rm -f nflogipacd nflogipacd.o
	rm -f nfnetlink_log_ctl.1.gz

install:nfnetlink_log_ctl nflogipacd nfnetlink_log_ctl.1.gz
	install -m755 -d ${DESTDIR}${SBINDIR}
	install -m755 nfnetlink_log_ctl ${DESTDIR}${SBINDIR}/nfnetlink_log_ctl
	install -m755 nflogipacd ${DESTDIR}${SBINDIR}/nflogipacd
	install -m755 -d ${DESTDIR}${MANDIR}/man1
	install -m644 nfnetlink_log_ctl.1.gz \
		${DESTDIR}${MANDIR}/man1/nfnetlink_log_ctl.1.gz

nfnetlink_log_ctl:nfnetlink_log_ctl.o
	${CC} ${CFLAGS} ${LIBS} $^ -o $@
nfnetlink_log_ctl.o:nfnetlink_log_ctl.c
nflogipacd:nflogipacd.o
	${CXX} ${CXXFLAGS} ${LIBS} ${BOOST_LIBS} $^ -o $@
nflogipacd.o:nflogipacd.cpp
nfnetlink_log_ctl.1.gz:nfnetlink_log_ctl.1

.PHONY: all clean install
