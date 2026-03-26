#!/bin/bash

# Network interface for localhost communication
IFACE="lo"

# Parameters for network simulation
DELAY="0ms"    # Add 100ms delay
LOSS="0%"       # Simulate 10% packet loss

# Function to apply network conditions
apply_network_conditions() {
    echo "Applying network conditions: $DELAY delay, $LOSS packet loss..."
    sudo tc qdisc add dev $IFACE root netem delay $DELAY loss $LOSS
}

# Function to remove network conditions
reset_network_conditions() {
    echo "Resetting network conditions..."
    sudo tc qdisc del dev $IFACE root netem
}

# Trap exit signal to clean up network settings
trap reset_network_conditions EXIT

# Apply network conditions
apply_network_conditions

# Start the server
echo "Starting server..."
python3 server.py &   # Run in the background
SERVER_PID=$!
sleep 1               # Allow time for the server to start

# Start the client
echo "Starting client..."
python3 client.py

# Wait for processes to finish
wait $SERVER_PID

