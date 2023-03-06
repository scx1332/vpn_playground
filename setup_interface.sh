#!/bin/bash
set -e

ip a
interface_name="vpn1"
ip link add $interface_name type dummy
ip link show $interface_name
ifconfig $interface_name hw ether C8:D7:4A:4E:47:50
ip addr add 192.168.1.100/24 brd + dev $interface_name label $interface_name:0
ip link set dev $interface_name up
ip a