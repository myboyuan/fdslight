#!/bin/bash
#服务端的iptables nat配置样例
#python3 fdslight_d.py -m server -d  start
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -F
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
