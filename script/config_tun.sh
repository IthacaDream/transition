#!/bin/bash
## by will song

#setup tun device
ip tuntap add dev tun0 mode tun
ip link set tun0 up

#add remote host ip to router
route add 219.223.195.140 dev tun0
