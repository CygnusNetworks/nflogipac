#!/bin/sh
#
# WARNING: THIS SCRIPT RESETS YOUR FIREWALL. USE AT YOUR OWN RISK.
# The script will setup traffic accounting for forwarded traffic
# (linux router) where eth0 is the WAN interface and eth1 the local
# interface

set -e

iptables -F
ip6tables -F

# Make sure the module is loaded or compiled in, otherwise nfnetlink_log_ctl
# will fail.
modprobe xt_NFLOG || true

# We need to set up the logging backend *before* adding rules. Otherwise your
# dmesg gets spammed if you also use -j LOG. See
# http://www.spinics.net/lists/netfilter/msg50123.html for further details.
./nfnetlink_log_ctl rebind AF_INET rebind AF_INET6

# A bigger --nflog-threshold reduces the per packet overhead.
iptables -A FORWARD -i eth0 -o eth1 -j NFLOG --nflog-group 1 --nflog-threshold 1024
iptables -A FORWARD -o eth0 -i eth1 -j NFLOG --nflog-group 2 --nflog-threshold 1024
ip6tables -A FORWARD -i eth0 -o eth1 -j NFLOG --nflog-group 3 --nflog-threshold 1024
ip6tables -A FORWARD -o eth0 -i eth1 -j NFLOG --nflog-group 4 --nflog-threshold 1024
