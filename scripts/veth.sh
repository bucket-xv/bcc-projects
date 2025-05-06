#! /bin/bash

# Create namespaces
sudo ip netns add red
sudo ip netns add blue

# Create veth pair
sudo ip link add veth-red type veth peer name veth-blue
sudo ip link set veth-red netns red
sudo ip link set veth-blue netns blue

# Set up veth0
sudo ip netns exec red ip addr add 10.0.1.1/24 dev veth-red
sudo ip netns exec blue ip addr add 10.0.1.2/24 dev veth-blue

sudo ip netns exec red ip link set veth-red up
sudo ip netns exec blue ip link set veth-blue up

# Add routes
sudo ip netns exec red ip route add 10.0.1.0/24 dev veth-red
sudo ip netns exec blue ip route add 10.0.1.0/24 dev veth-blue

# Ping
sudo ip netns exec red ping 10.0.1.2
sudo ip netns exec blue ping 10.0.1.1