# Kubernetes Attack Simulation Lab

A comprehensive hands-on lab demonstrating real-world Kubernetes security threats and runtime detection using **Falco** and **Falco Talon** for automated incident response. This lab simulates a multi-stage attack chain mapped to the MITRE ATT&CK framework and measures Mean Time To Respond (MTTR) metrics.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Lab Setup](#lab-setup)
- [Attack Simulation](#attack-simulation)
- [Security Monitoring & Response](#security-monitoring--response)
- [Metrics Collection & Analysis](#metrics-collection--analysis)
- [Attack Techniques (MITRE ATT&CK)](#attack-techniques-mitre-attck)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

This lab demonstrates:

- **Initial Access**: Exploiting a misconfigured Jupyter Notebook with excessive privileges
- **Execution**: Deploying a privileged attack pod from a compromised container
- **Persistence**: Establishing cron jobs and LD_PRELOAD hooks
- **Privilege Escalation**: Container escape via chroot to host filesystem
- **Defense Evasion**: Process masquerading, history clearing, hidden directories
- **Credential Access**: Extracting Kubernetes service account tokens and cloud credentials
- **Discovery**: Network scanning and host enumeration
- **Command & Control**: Reverse shell connections to C2 server
- **Exfiltration**: Data exfiltration to external server
- **Impact**: Cryptomining with XMRig

The lab uses **Falco** for runtime threat detection with custom rules and **Falco Talon** for automated response actions (network isolation, log collection, packet capture).

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Minikube Cluster                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐         ┌──────────────────┐          │
│  │ Jupyter Notebook │         │ Payload Server   │          │
│  │ (Vulnerable)     │────────▶│ (C2 Server)      │          │
│  │ - Privileged     │         │ - Hosts payloads │          │
│  │ - Host mount /   │         │ - Receives data  │          │
│  │ - cluster-admin  │         │ - Reverse shells │          │
│  └──────────────────┘         └──────────────────┘          │
│          │                                                    │
│          │ Deploys                                           │
│          ▼                                                    │
│  ┌──────────────────┐                                        │
│  │ Attack-Sim Pod   │                                        │
│  │ - Privileged     │                                        │
│  │ - Host mount /   │                                        │
│  │ - Multi-stage    │                                        │
│  └──────────────────┘                                        │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            Falco Security Stack                       │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │   │
│  │  │  Falco   │─▶│  Talon   │─▶│  Sidekick UI     │  │   │
│  │  │ (Detect) │  │(Response)│  │  (Dashboard)     │  │   │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Components**:
- **Jupyter Notebook**: Intentionally misconfigured pod serving as initial access point
- **Payload Server**: HTTP server hosting malicious payloads and receiving exfiltrated data
- **Attack-Sim Pod**: Automated attacker container executing the kill chain
- **Falco**: Runtime security monitoring with eBPF/modern-bpf driver
- **Falco Talon**: Automated response engine for threat containment
- **Falco Sidekick UI**: Web dashboard for visualizing security events

---

## ✅ Prerequisites

- **Docker** (version 20.x or higher)
- **Minikube** (version 1.30.x or higher)
- **kubectl** (matching your Kubernetes version)
- **Helm** (version 3.x)
- **Python 3** (for metrics collection)
- At least **4GB RAM** and **20GB disk space** available for Minikube

---

## 🚀 Lab Setup

### Step 1: Start the Kubernetes Cluster

Start a new Minikube cluster using the Docker driver:

```bash
minikube start --driver=docker
```

**CRITICAL**: Configure your terminal to use Minikube's internal Docker daemon. This ensures all images are built in the right environment:

```bash
eval $(minikube -p minikube docker-env)
```

### Step 2: Build the Docker Images

Ensure you are in the `k8s-attack-simulation-lab/` directory, then build all three container images:

```bash
# Build the vulnerable Jupyter Notebook image
docker build -t insecure-jupyter:latest ./jupyter-notebook

# Build the payload-server (C2) image
docker build -t payload-server:latest ./payload-server

# Build the attack-sim (attacker) image
docker build -t attack-sim:latest ./attack-sim
```

Verify the images are available:

```bash
docker images | grep -E 'insecure-jupyter|payload-server|attack-sim'
```

### Step 3: Deploy the Initial Infrastructure

Deploy the vulnerable infrastructure before installing Falco:

```bash
# Grant the default service account cluster-admin privileges (DANGEROUS - intentional misconfiguration)
kubectl apply -f kubernetes/0-jupyter-rbac.yaml

# Deploy the payload-server (C2)
kubectl apply -f kubernetes/1-payload-server.yaml

# Deploy the vulnerable Jupyter Notebook pod
kubectl apply -f kubernetes/0-jupyter-deploy.yaml
```

Watch the pods start up (wait for them to be in 'Running' state):

```bash
kubectl get pods -w
```

Press `Ctrl+C` when all pods are running.

### Step 4: Install Falco Security Stack

Add the Falco Helm repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Install Falco with custom rules and Talon automated response:

```bash
helm upgrade --install falco falcosecurity/falco \
  -n falco --create-namespace \
  -f values-falco-custom.yaml
```

Wait for all Falco components to be ready:

```bash
kubectl get pods -n falco -w
```

Verify Falco installation:

```bash
kubectl get pods -n falco
```

You should see:
- `falco-*` (DaemonSet pods)
- `falco-falcosidekick-*`
- `falco-falcosidekick-ui-*`
- `falco-talon-*`
- `falco-talon-nats-*`

### Step 5: Access Falco Sidekick UI (Optional)

Open the Falco dashboard to visualize security events in real-time:

```bash
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802
```

Open your browser and navigate to: **http://127.0.0.1:2802**  
Default credentials: `admin` / `admin`

---

## 🎭 Attack Simulation

### Phase 1: Initial Access

Expose the vulnerable Jupyter Notebook:

```bash
kubectl expose deployment misconfigured-jupyter --type=NodePort --port=8888
kubectl rollout status deployment/misconfigured-jupyter
minikube service misconfigured-jupyter --url
```

This will output a URL like `http://192.168.49.2:31234`. Open this URL in your web browser.

### Phase 2: Execution - Deploy Attack Pod

In the Jupyter UI:
1. Click **New → Terminal** (top-right)
2. You now have a root shell inside the compromised pod

In the Jupyter terminal, create the attack-sim pod manifest:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: sim-pod
  namespace: default
  labels:
    app: attack-sim
  annotations:
    container.apparmor.security.beta.kubernetes.io/attack-sim: unconfined
spec:
  containers:
  - name: attack-sim
    image: attack-sim:latest
    imagePullPolicy: Never
    securityContext:
      privileged: true
      runAsUser: 0
      capabilities:
        add: ["ALL"]
      seccompProfile:
        type: Unconfined
    env:
    - name: PAYLOAD_SERVER
      value: "payload-server.default.svc.cluster.local"
    - name: PAYLOAD_SERVER_PORT
      value: "8080"
    volumeMounts:
    - name: docker-sock
      mountPath: /var/run/docker.sock
    - name: host-fs
      mountPath: /host
  volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
  - name: host-fs
    hostPath:
      path: /
EOF
```

### Phase 3: Multi-Stage Attack Chain

The attack pod will automatically execute the following attack chain:

1. **Defense Evasion**: Remove immutable attributes from system binaries
2. **Persistence**: Install LD_PRELOAD hook (`/etc/ld.so.preload`)
3. **Persistence**: Create cron job for miner persistence
4. **Privilege Escalation**: Attempt container escape via legacy `noumt` technique
5. **Privilege Escalation**: Container escape via `chroot /host`
6. **Defense Evasion**: Create hidden directories (`/dev/shm/.../...HIDDEN.../`)
7. **Credential Access**: Extract Kubernetes service account tokens
8. **Exfiltration**: Send stolen credentials to C2 server
9. **Credential Access**: Search for AWS credentials and secrets
10. **Discovery**: Port scanning the C2 server
11. **Command & Control**: Attempt reverse shell connections (ports 4444, 7456)
12. **Defense Evasion**: Read `/etc/shadow` via symlink
13. **Defense Evasion**: Execute binary masquerading as Python script
14. **Defense Evasion**: Clear bash history
15. **Impact**: Execute XMRig cryptominer

Monitor the attack in real-time:

```bash
# Watch Falco events
kubectl logs -n falco -l app.kubernetes.io/name=falco -f | grep --color=always -E "Priority|rule"

# Watch Talon responses
kubectl logs -n falco -l app.kubernetes.io/name=falco-talon -f

# Monitor attack pod logs
kubectl logs -f sim-pod
```

---

## 🛡️ Security Monitoring & Response

### Falco Detection Rules

The lab includes **18 custom Falco rules** covering the full attack chain:

**Initial Access & Execution**:
- Privileged Pod with Root Filesystem Mount

**Persistence**:
- Cron Job Planted for Persistence
- Suspicious LD_PRELOAD Modification

**Privilege Escalation**:
- Container Escape via Chroot

**Defense Evasion**:
- File Attribute Modification
- Hidden Directory Creation
- Masquerading as Python Script
- Command History Deletion
- Read Shadow File via Symlink

**Credential Access**:
- K8s Token Read by Shell or Script
- Cloud Credential Discovery

**Discovery & C2**:
- Network Port Scan with Python
- Outbound Connection to Suspicious Port

**Exfiltration & Impact**:
- Data Exfiltration via Python
- Cryptominer Process Detected

### Automated Response Actions (Falco Talon)

Talon automatically responds to critical threats:

**Response to Data Exfiltration**:
- Collect last 500 lines of pod logs
- Capture network traffic (15s tcpdump)
- Isolate pod egress with NetworkPolicy
- Label pod: `falco.remediated=true`, `falco.reason=exfil`

**Response to C2 Connection**:
- Collect logs and network traffic
- Block outbound connections
- Label suspicious pod

**Response to Token Theft**:
- Collect logs
- Isolate network egress
- Download the stolen token for forensics
- Label pod

View Talon actions:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco-talon --tail=100
```

Check network policies created by Talon:

```bash
kubectl get networkpolicies
```

---

## 📊 Metrics Collection & Analysis

### Collect MTTR (Mean Time To Respond) Data

After the attack completes, run the metrics collection script:

```bash
python3 metrics.py
```

This script:
- Extracts Falco detection events from pod logs
- Correlates with Talon response actions
- Calculates MTTR for each threat
- Outputs a summary and saves `mttr_events.csv`

**Sample Output**:
```
2024-11-04T10:23:15+00:00  Data Exfiltration via Python -> 2024-11-04T10:23:18+00:00  MTTR=3.245s  [rule-match]
2024-11-04T10:23:20+00:00  Outbound Connection to Suspicious Port -> 2024-11-04T10:23:22+00:00  MTTR=1.987s  [rule-match]
...

SUMMARY
count=15  mean=2.456s  median=2.123s  p90=4.567s  max=6.789s
```

### Visualize Results

Open the Jupyter notebook for plotting:

```bash
# If you have Jupyter installed locally
jupyter notebook plots.ipynb

# Or use the provided Jupyter pod (after stopping the attack)
kubectl port-forward deployment/misconfigured-jupyter 8888:8888
# Open http://localhost:8888 and navigate to plots.ipynb
```

The notebook generates:
- MTTR distribution histogram
- Timeline of detection vs. response
- Rule-wise MTTR comparison
- P50, P90, P99 percentile analysis

---

## 🎯 Attack Techniques (MITRE ATT&CK)

This lab demonstrates techniques from multiple MITRE ATT&CK tactics:

| **Tactic** | **Technique ID** | **Technique Name** | **Implementation** |
|------------|------------------|--------------------|--------------------|
| Initial Access | T1190 | Exploit Public-Facing Application | Exposed Jupyter Notebook |
| Execution | T1609 | Container Administration Command | kubectl to deploy attack pod |
| Persistence | T1053.003 | Scheduled Task: Cron | Cron job for miner |
| Persistence | T1574.006 | Hijack Execution Flow: LD_PRELOAD | hook.so in /etc/ld.so.preload |
| Privilege Escalation | T1611 | Escape to Host | chroot to /host |
| Defense Evasion | T1222.002 | File Permissions Modification | chattr -i |
| Defense Evasion | T1564.001 | Hidden Files and Directories | /dev/shm/.../... |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name | Binary as .py |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | Clear bash_history |
| Credential Access | T1552.001 | Unsecured Credentials: Files | ServiceAccount token |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | Read /etc/shadow |
| Discovery | T1046 | Network Service Discovery | Port scanning |
| Discovery | T1613 | Container and Resource Discovery | Host filesystem enumeration |
| Command and Control | T1071.001 | Application Layer Protocol: Web | HTTP C2 |
| Command and Control | T1105 | Ingress Tool Transfer | Download payloads via curl |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | POST stolen data |
| Impact | T1496 | Resource Hijacking | Cryptomining with XMRig |

---

## 🧹 Cleanup

To completely remove the lab environment:

```bash
# Delete attack and vulnerable pods
kubectl delete pod sim-pod
kubectl delete deployment misconfigured-jupyter
kubectl delete service misconfigured-jupyter
kubectl delete deployment payload-server
kubectl delete service payload-server

# Remove RBAC configuration
kubectl delete -f kubernetes/0-jupyter-rbac.yaml

# Uninstall Falco
helm uninstall falco -n falco
kubectl delete namespace falco

# Stop Minikube
minikube stop

# (Optional) Delete Minikube cluster completely
minikube delete
```

---

## 🔧 Troubleshooting

### Images Not Found

**Issue**: `ImagePullBackOff` or `ErrImageNeverPull`

**Solution**: Ensure you ran `eval $(minikube docker-env)` before building images:
```bash
eval $(minikube docker-env)
docker images | grep -E 'insecure-jupyter|payload-server|attack-sim'
```

### Falco Not Detecting Events

**Issue**: No logs in Falco pods

**Solution**: Check Falco is running:
```bash
kubectl get pods -n falco
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50
```

### Talon Not Responding

**Issue**: Falco detects but Talon doesn't act

**Solution**: Verify Talon configuration:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco-talon --tail=100
kubectl get configmap -n falco falco-talon -o yaml
```

### Payload Server Unreachable

**Issue**: Attack pod can't download payloads

**Solution**: Verify service DNS resolution:
```bash
kubectl exec sim-pod -- nslookup payload-server.default.svc.cluster.local
kubectl get svc payload-server
```

### Metrics Script Fails

**Issue**: `metrics.py` shows no events

**Solution**: Adjust the time window in `metrics.py`:
```python
SINCE = "30000m"  # Increase to look further back
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests for:
- Additional attack techniques
- New Falco detection rules
- Enhanced Talon response actions
- Documentation improvements

---

## ⚠️ Disclaimer

This lab is for **educational purposes only**. The techniques demonstrated should only be used in controlled environments for learning and testing. Never deploy intentionally vulnerable configurations in production environments.

---

## 📖 References

- [Falco Documentation](https://falco.org/docs/)
- [Falco Talon](https://docs.falco-talon.org/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)

---
