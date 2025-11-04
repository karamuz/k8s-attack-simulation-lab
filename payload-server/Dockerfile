FROM python:3.9-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV HTTP_PORT=8080
ENV SHELL_PORT_1=4444
ENV SHELL_PORT_2=7456

# Install necessary tools
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Create payload directory structure
WORKDIR /payloads
RUN mkdir -p uploads shells

# Copy the server scripts
COPY server.py .
COPY shell_logger.sh .
COPY entrypoint.sh .

# Copy all payloads into the image
COPY ./payloads/ .

# Set executable permissions
RUN chmod +x server.py shell_logger.sh entrypoint.sh *

# Expose ports
EXPOSE ${HTTP_PORT} ${SHELL_PORT_1} ${SHELL_PORT_2} 4445

# Start services
CMD ["/payloads/entrypoint.sh"]