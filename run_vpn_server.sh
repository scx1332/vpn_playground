#!/bin/bash
echo "Starting VPN server"
/novpn-c/novpn 45918
wait_sec=10000000
echo "Waiting for $wait_sec seconds before leaving the container..."
sleep $wait_sec
echo "Leaving the container..."
