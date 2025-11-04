#!/bin/bash
PORT=$1
LOG_FILE="/payloads/shells/shell_${PORT}_$(date +%s).log"

echo "Starting PERSISTENT listener on port $PORT, logging to $LOG_FILE"
echo "Listener started at $(date)" > $LOG_FILE

# This loop ensures the listener never exits after a connection.
while true; do
    if command -v nc.traditional &> /dev/null; then
        # The stdbuf command ensures logs are written immediately.
        # The tee command logs both to console and to the file.
        stdbuf -o0 nc.traditional -l -p $PORT -v < /dev/null 2>&1 | tee -a $LOG_FILE
    elif command -v nc.openbsd &> /dev/null; then
        stdbuf -o0 nc.openbsd -l -p $PORT -v < /dev/null 2>&1 | tee -a $LOG_FILE
    else
        stdbuf -o0 nc -l -p $PORT -v < /dev/null 2>&1 | tee -a $LOG_FILE
    fi
    # Add a small delay to prevent high CPU usage if nc fails instantly
    sleep 1
done