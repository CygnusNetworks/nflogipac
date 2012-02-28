#include <arpa/inet.h>
#include <endian.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

#include <boost/bind.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#ifndef RECEIVE_BUFFER_SIZE
/* TODO: should this be runtime configurable? */
#define RECEIVE_BUFFER_SIZE 1024*1024
#endif

#ifdef USE_STANDARD_MAP
#include <map>
#else
#include <boost/tr1/unordered_map.hpp>
#endif

extern "C" {
#include <libnetfilter_log/libnetfilter_log.h>
}

#if defined(__GNUC__) && __GNUC__ > 3
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#define CMD_ACCOUNT 1u
#define CMD_END 2u

/**
 * Generic error nflogipac error class.
 */
class nflogipac_error : public std::exception {
	public:
		const char *const message;
		nflogipac_error(const char *m) : message(m) {}
};

/**
 * Base class for traffic counters. Invoking the methods count, packet_lost and
 * writedata in different threads must be safe.
 */
class nflogipac_counter {
	protected:
		boost::mutex lock;
		unsigned int packets_lost;
	public:
		const size_t caplen;
		nflogipac_counter(size_t cl) : packets_lost(0), caplen(cl) {}
		/**
		 * Account a given packet.
		 * @param payload is a buffer of precisely caplen bytes
		 */
		virtual void count(const char *payload)=0;
		/**
		 * Report loss of packets. This can happen if the kernel fills
		 * the receive buffer faster than we empty it.
		 */
		void packet_lost();
		/**
		 * Write current accounting data to the given ostream.
		 * @returns whether writing was successful
		 */
		virtual bool writedata(std::ostream &out)=0;
};

/**
 * OOP interface to libnetfilter_log. This class is not thread safe by itself.
 */
class nflogipac {
	private:
		struct nflog_handle *handle;
		struct nflog_g_handle *ghandle;
		uint16_t group;
		nflogipac_counter *counter;
		int fd;

		int receive();
	public:
		nflogipac(uint16_t g, nflogipac_counter *c);
		void open();
		void count(const char *payload, size_t length);
		void run();
};

void nflogipac_counter::packet_lost() {
	boost::lock_guard<boost::mutex> lock(this->lock);
	++this->packets_lost;
}

struct ipv4_hash : public std::unary_function<std::string, size_t> {
	size_t operator()(const std::string &s) const;
};

class nflogipac_counter_ipv4 : public nflogipac_counter {
	private:
#ifdef USE_STANDARD_MAP
		typedef std::map<std::string, uint64_t> counter_map_type;
#else
		typedef std::tr1::unordered_map<std::string, uint64_t,
			ipv4_hash> counter_map_type;
#endif
		counter_map_type counters;
		const unsigned int netmask;
	protected:
		virtual std::string getaddress(const char *payload) const=0;
	public:
		nflogipac_counter_ipv4(size_t cl, unsigned int nm=32u);
		void count(const char *payload);
		bool writedata(std::ostream &out);
};

class nflogipac_counter_ipv4src : public nflogipac_counter_ipv4 {
	protected:
		std::string getaddress(const char *payload) const;
	public:
		nflogipac_counter_ipv4src(unsigned int nm=32u)
			: nflogipac_counter_ipv4(16u, nm) {}
};

class nflogipac_counter_ipv4dst : public nflogipac_counter_ipv4 {
	protected:
		std::string getaddress(const char *payload) const;
	public:
		nflogipac_counter_ipv4dst(unsigned int nm=32u)
			: nflogipac_counter_ipv4(20u, nm) {}
};

struct ipv6_hash : public std::unary_function<std::string, size_t> {
	size_t operator()(const std::string &s) const;
};

class nflogipac_counter_ipv6 : public nflogipac_counter {
	private:
#ifdef USE_STANDARD_MAP
		typedef std::map<std::string, uint64_t> counter_map_type;
#else
		typedef std::tr1::unordered_map<std::string, uint64_t,
			ipv6_hash> counter_map_type;
#endif
		counter_map_type counters;
		const unsigned int netmask;
	protected:
		virtual std::string getaddress(const char *payload) const=0;
	public:
		nflogipac_counter_ipv6(size_t cl, unsigned int nm=128u);
		void count(const char *payload);
		bool writedata(std::ostream &out);
};

class nflogipac_counter_ipv6src : public nflogipac_counter_ipv6 {
	protected:
		std::string getaddress(const char *payload) const;
	public:
		nflogipac_counter_ipv6src(unsigned int nm=128u)
			: nflogipac_counter_ipv6(24u, nm) {}
};

class nflogipac_counter_ipv6dst : public nflogipac_counter_ipv6 {
	protected:
		std::string getaddress(const char *payload) const;
	public:
		nflogipac_counter_ipv6dst(unsigned int nm=128u)
			: nflogipac_counter_ipv6(40u, nm) {}
};

nflogipac::nflogipac(uint16_t g, nflogipac_counter *c)
		: handle(0), group(g), counter(c) {
}

extern "C" {
	nflog_callback callback;
}

void nflogipac::open() {
	this->handle = ::nflog_open();
	if(0 == this->handle)
		throw nflogipac_error("nflog_open failed");
	this->fd = ::nflog_fd(this->handle);

	try {
		{
			socklen_t rcvbuf(RECEIVE_BUFFER_SIZE);
			if(::setsockopt(this->fd, SOL_SOCKET, SO_RCVBUFFORCE,
						&rcvbuf, sizeof(rcvbuf)) < 0)
				throw nflogipac_error("setsockopt(..., "
						"SO_RCVBUFFORCE, ...) failed");
		}

		this->ghandle = ::nflog_bind_group(this->handle, this->group);
		if(0 == this->ghandle)
			throw nflogipac_error("nflog_bind_group failed");
		try {
			if(::nflog_set_mode(this->ghandle, NFULNL_COPY_PACKET,
						this->counter->caplen) < 0)
				throw nflogipac_error("nflog_set_mode " 
						"NFUNL_COPY_PACKET failed");
			if(::nflog_callback_register(this->ghandle, &callback,
						this) < 0)
				throw nflogipac_error("nflog_callback_register "
						"failed");
		} catch(nflogipac_error) {
			::nflog_unbind_group(this->ghandle);
			this->ghandle = 0;
			throw;
		}
	} catch(nflogipac_error) {
		::nflog_close(this->handle);
		this->handle = 0;
		throw;
	}
}

extern "C" {

int callback(struct nflog_g_handle *g UNUSED, struct nfgenmsg *m UNUSED,
		struct nflog_data *d, void *p) {
	char *payload;
	const int l(::nflog_get_payload(d, &payload));
	static_cast<nflogipac*>(p)->count(payload, l);
	return 0;
}

}

int nflogipac::receive() {
	/* FIXME: magic constant */
	char buf[65536];
	const int r(recv(this->fd, buf, sizeof(buf), 0u));
	if(r > 0)
		::nflog_handle_packet(this->handle, buf, r);
	return r;
}

void nflogipac::count(const char *payload, size_t length) {
	if(length < this->counter->caplen)
		return;
	this->counter->count(payload);
}

void nflogipac::run() {
	for(;;) {
		errno = 0;
		if(this->receive() > 0)
			continue;
		if(ENOBUFS == errno) {
			this->counter->packet_lost();
			continue;
		}
		std::cerr << "recv error " << std::strerror(errno) << std::endl;
		std::exit(1);
	}
}

inline uint16_t readuint16(const char data[2]) {
	uint16_t tmp;
	std::memcpy(&tmp, data, 2u);
	return ntohs(tmp);
}

inline void writeuint16(char data[2], uint16_t value) {
	value = htons(value);
	std::memcpy(data, &value, 2u);
}

inline bool writeuint16stream(std::ostream &out, uint16_t value) {
	char buf[2u];
	writeuint16(buf, value);
	return out.write(buf, CMD_END).good();
}

void applynetmask(std::string &address, unsigned int netmask) {
	const unsigned int bytes(netmask / 8);
	assert(address.size() >= bytes);
	if(bytes < address.size()) {
		const unsigned char bitmask(~(unsigned char)
				(0xffu >> (netmask % 8u)));
		((unsigned char&)address[bytes]) &= bitmask;
		std::fill(&address[bytes+1u], &address[address.size()], 0u);
	}
}

inline size_t ipv4_hash::operator()(const std::string &s) const {
	assert(4u == s.size());
	size_t ret(0u);
	std::memcpy(&ret, s.data(), 4u);
	return ret;
}

nflogipac_counter_ipv4::nflogipac_counter_ipv4(size_t cl, unsigned int nm)
		: nflogipac_counter(std::max((size_t)4, cl)), netmask(nm) {
	assert(nm <= 32u);
}

void nflogipac_counter_ipv4::count(const char *payload) {
	const uint64_t totlen(readuint16(payload+2u));
	std::string addr(this->getaddress(payload));
	applynetmask(addr, this->netmask);
	boost::lock_guard<boost::mutex> lock(this->lock);
	this->counters[addr] += std::max((uint64_t)20u, totlen);
}

std::string nflogipac_counter_ipv4src::getaddress(const char *payload) const {
	return std::string(payload+12u, 4u);
}

std::string nflogipac_counter_ipv4dst::getaddress(const char *payload) const {
	return std::string(payload+16u, 4u);
}

inline size_t ipv6_hash::operator()(const std::string &s) const {
	/* Assumption: sizeof(size_t) is a power of two. */
	static const unsigned int size_t_size(std::min(16u,
				(unsigned int)sizeof(size_t)));
	assert(16u == s.size());
	size_t ret(0u);
	std::memcpy(&ret, s.data(), size_t_size);
	for(unsigned int i(size_t_size);
			i < 16u; i += size_t_size) {
		size_t tmp(0u);
		std::memcpy(&tmp, s.data() + i, size_t_size);
		ret ^= tmp;
	}
	return ret;
}

nflogipac_counter_ipv6::nflogipac_counter_ipv6(size_t cl, unsigned int nm)
		: nflogipac_counter(std::max((size_t)6, cl)), netmask(nm) {
			assert(nm <= 128u);
}

void nflogipac_counter_ipv6::count(const char *payload) {
	const uint64_t totlen((uint64_t)40u + (uint64_t)readuint16(payload+4u));
	std::string addr(this->getaddress(payload));
	applynetmask(addr, this->netmask);
	boost::lock_guard<boost::mutex> lock(this->lock);
	this->counters[addr] += totlen;
}

std::string nflogipac_counter_ipv6src::getaddress(const char *payload) const {
	return std::string(payload+8u, 16u);
}

std::string nflogipac_counter_ipv6dst::getaddress(const char *payload) const {
	return std::string(payload+24u, 16u);
}

unsigned int str2int(const std::string &str) {
	std::stringstream ss(str);
	unsigned int result;
	if((ss >> result).fail())
		throw nflogipac_error("not a number");
	return result;
}

nflogipac_counter *make_counter(const std::string &str) {
	if(0 == str.compare("ipv4src"))
		return new nflogipac_counter_ipv4src();
	if(0 == str.compare(0, 8, "ipv4src/"))
		try {
			const unsigned int mask(str2int(str.substr(8)));
			if(mask > 32)
				return 0;
			return new nflogipac_counter_ipv4src(mask);
		} catch(nflogipac_error) {
			return 0;
		}
	if(0 == str.compare("ipv4dst"))
		return new nflogipac_counter_ipv4dst();
	if(0 == str.compare(0, 8, "ipv4dst/"))
		try {
			const unsigned int mask(str2int(str.substr(8)));
			if(mask > 32)
				return 0;
			return new nflogipac_counter_ipv4dst(mask);
		} catch(nflogipac_error) {
			return 0;
		}
	if(0 == str.compare("ipv6src"))
		return new nflogipac_counter_ipv6src();
	if(0 == str.compare(0, 8, "ipv6src/"))
		try {
			const unsigned int mask(str2int(str.substr(8)));
			if(mask > 128)
				return 0;
			return new nflogipac_counter_ipv6src(mask);
		} catch(nflogipac_error) {
			return 0;
		}
	if(0 == str.compare("ipv6dst"))
		return new nflogipac_counter_ipv6dst();
	if(0 == str.compare(0, 8, "ipv6dst/"))
		try {
			const unsigned int mask(str2int(str.substr(8)));
			if(mask > 128)
				return 0;
			return new nflogipac_counter_ipv6dst(mask);
		} catch(nflogipac_error) {
			return 0;
		}
	return 0;
}

bool write_count_message(std::ostream &out, const std::string &address,
		uint64_t value) {
	char buf[8u];
	const unsigned int msgsize(2u + 2u + 8u + address.size());
	if(!writeuint16stream(out, msgsize))
		return false;
	if(!writeuint16stream(out, CMD_ACCOUNT))
		return false;
#if BYTE_ORDER == LITTLE_ENDIAN
	std::reverse_copy((const char*)&value, 8u+(const char*)&value, buf);
#else
	std::memcpy(buf, &value, 8u)
#endif
	if(!out.write(buf, 8u).good())
		return false;
	return out.write(address.data(), address.size()).good();
}

bool write_end_message(std::ostream &out) {
	static const unsigned int msgsize(2u + 2u);
	return writeuint16stream(out, msgsize) && writeuint16stream(out, 2);
}

bool write_loss_message(std::ostream &out, unsigned int value) {
	static const unsigned int msgsize(2u + 2u + 2u),
		     uint16max(std::numeric_limits<uint16_t>::max());
	return writeuint16stream(out, msgsize) && writeuint16stream(out, 3u) &&
		writeuint16stream(out, std::min(value, uint16max));
}

bool nflogipac_counter_ipv4::writedata(std::ostream &out) {
	counter_map_type exportcounters;
	unsigned int export_packets_lost(0);
	{
		boost::lock_guard<boost::mutex>
			lg(this->lock);
		/* Fetch and clear counters. */
		exportcounters.swap(this->counters);
		std::swap(export_packets_lost, this->packets_lost);
	}
	if(export_packets_lost > 0)
		if(!write_loss_message(out, export_packets_lost))
			return false;
	for(counter_map_type::iterator i(exportcounters.begin());
				i != exportcounters.end(); ++i)
		if(!write_count_message(out, i->first, i->second))
			return false;
	return write_end_message(out) && out.flush().good();
}

bool nflogipac_counter_ipv6::writedata(std::ostream &out) {
	counter_map_type exportcounters;
	unsigned int export_packets_lost(0);
	{
		boost::lock_guard<boost::mutex>
			lg(this->lock);
		/* Fetch and clear counters. */
		exportcounters.swap(this->counters);
		std::swap(export_packets_lost, this->packets_lost);
	}
	if(export_packets_lost > 0)
		if(!write_loss_message(out, export_packets_lost))
			return false;
	for(counter_map_type::iterator i(exportcounters.begin());
				i != exportcounters.end(); ++i)
		if(!write_count_message(out, i->first, i->second))
			return false;
	return write_end_message(out) && out.flush().good();
}

int reportloop(nflogipac_counter *counter) {
	for(;;) {
		{
			char buf;
			/* Use read to avoid buffered IO. */
			int r(read(STDIN_FILENO, &buf, 1));
			/* r == 0: EOF => terminate cleanly
			 * r < 0: some error => terminate with error */
			if(1 > r)
				return r < 0 ? 1 : 0;
		}
		if(!counter->writedata(std::cout))
			return 1;
	}
}

int main(int argc, char **argv) {
	if(3 != argc) {
		std::cerr << "takes precisely 2 arguments: group counter"
			<< std::endl
			<< "group is the netlink group number" << std::endl
			<< "counter is one out of ipv[46]{src,dst} with an "
			<< "optional netmask"
			<< std::endl;
		return 1;
	}

	unsigned int group;
	try {
		group = str2int(argv[1]);
	} catch(nflogipac_error) {
		std::cerr << "first parameter must be a number" << std::endl;
		return 1;
	}

	nflogipac_counter *counter(make_counter(argv[2]));
	if(0 == counter) {
		std::cerr << "second parameter must be one matching "
			<< "ipv[46]{src,dst}(/[0-9]+)?" << std::endl;
		return 1;
	}

	nflogipac f(group, counter);
	try {
		f.open();
	} catch(nflogipac_error &err) {
		std::cerr << "error: " << err.message << std::endl;
		return 1;
	}

	boost::thread nflogthread(boost::bind(&nflogipac::run, &f));

	std::exit(reportloop(counter));
}
