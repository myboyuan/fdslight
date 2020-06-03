#!/bin/sh

iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT

insmod ./driver/xt_FULLCONENAT.ko

