CC = gcc
CFLAGS = -W -Wall -Wextra -pedantic -ansi
CXX = g++
CXXFLAGS = -W -Wall -Wextra -pedantic -O2
LIBS = -lnetfilter_log
BOOST_LIBS = -lboost_thread

%.o:%.c
	${CC} ${CFLAGS} -c $< -o $@

%.o:%.cpp
	${CXX} ${CXXFLAGS} -c $< -o $@

all:nfnetlink_log_ctl nflogipacd
clean:
	rm -f nfnetlink_log_ctl nfnetlink_log_ctl.o
	rm -f nflogipacd nflogipacd.o

nfnetlink_log_ctl:nfnetlink_log_ctl.o
	${CC} ${CFLAGS} ${LIBS} $^ -o $@
nfnetlink_log_ctl.o:nfnetlink_log_ctl.c
nflogipacd:nflogipacd.o
	${CXX} ${CXXFLAGS} ${LIBS} ${BOOST_LIBS} $^ -o $@
nflogipacd.o:nflogipacd.cpp
