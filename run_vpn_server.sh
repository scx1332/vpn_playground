#!/bin/bash
echo "Starting VPN server"
cd novpn-c
./novpn server ${VPN_SERVER_PORT:-45918}
wait_sec=10000000
echo "Waiting for $wait_sec seconds before leaving the container..."
sleep $wait_sec
echo "Leaving the container..."
