#!/bin/bash
echo "Starting VPN client"
wait_sec=10000000
echo "Waiting for $wait_sec seconds before leaving the container..."
sleep $wait_sec
echo "Leaving the container..."
