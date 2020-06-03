#!/bin/bash

# 禁止USB设备休眠，比如USB网卡
for dev in /sys/bus/usb/devices/*/power/control; do
        echo $dev
        echo on > $dev
done
