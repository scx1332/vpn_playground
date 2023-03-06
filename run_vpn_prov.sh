#!/bin/bash
echo "Starting VPN client"
cd /vpn/novpn-c
sleep 3
vpn_server_ip=$(dig +short vpn_server)
vpn_server_port=45918
vpn_client_id=${VPN_CLIENT_ID:-0}
echo "Connecting to VPN server IP: $vpn_server_ip and port: $vpn_server_port with id: $vpn_client_id"
./novpn client ${vpn_server_ip} ${vpn_server_port} ${vpn_client_id}&
sleep 2
echo "Checking IP: $vpn_server_ip and port: $vpn_server_port"
ifconfig
cd /vpn
python -u server.py
wait_sec=10
echo "Waiting for $wait_sec seconds before leaving the container..."
sleep $wait_sec
echo "Leaving the container..."
