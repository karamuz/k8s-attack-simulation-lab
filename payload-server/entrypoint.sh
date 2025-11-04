#!/bin/bash

echo "Starting payload server..."
echo "HTTP_PORT: $HTTP_PORT"
echo "SHELL_PORT_1: $SHELL_PORT_1"
echo "SHELL_PORT_2: $SHELL_PORT_2"

# Start HTTP server in the background
python3 /payloads/server.py &

# Start shell listeners with logging in the background
/payloads/shell_logger.sh $SHELL_PORT_1 &
/payloads/shell_logger.sh $SHELL_PORT_2 &

# Create a simple echo server for testing basic connectivity
(while true; do { echo -e "HTTP/1.1 200 OK\n\n$(date) - Simple Echo Server"; } | nc -l -p 4445; done) &

# Keep container running
echo "All services started. Tailing logs..."
tail -f /dev/null