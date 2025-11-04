#!/usr/bin/env python3
# MTTR (Falco detect -> Talon response)
import subprocess, json, re, statistics, sys
from datetime import datetime, timezone
import csv, statistics

# ===== CONFIG =====
NAMESPACE = "falco"
DS_NAME   = "falco"         # Falco DaemonSet name
TALON_DEP = "falco-talon"   # Talon Deployment name
SINCE     = "18000m"          # how far back to read logs

ONLY_RULES = [
    # "Data Exfiltration via Python",
    # "Outbound Connection to Suspicious Port",
    # "K8s Token Read by Shell or Script",
]
# if no rule string on Talon lines, accept first Talon action within this window
MAX_LOOKAHEAD_SEC = 900
# require Talon line to show an *action* (reduces noise)
TALON_ACTION_KEYWORDS = ("notification", "Executing action", "Action executed successfully")
# ==================

def sh(cmd:list)->str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

def kjson(cmd:list)->dict:
    return json.loads(sh(cmd))

def parse_ts_prefix(line:str):
    try:
        ts = line.split()[0]
        if ts.endswith("Z"): ts = ts.replace("Z","+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def parse_falco_time(iso_str:str)->datetime:
    s = iso_str.strip()
    if s.endswith("Z"): s = s[:-1]
    if "." in s:
        base, frac = s.split(".", 1)
        frac = (frac + "000000")[:6]
        s = f"{base}.{frac}+00:00"
    else:
        s = s + "+00:00"
    return datetime.fromisoformat(s)

def get_falco_lines_all(ns, ds_name, since):
    ds = kjson(["kubectl","-n",ns,"get","ds",ds_name,"-o","json"])
    sel = ",".join(f"{k}={v}" for k,v in ds["spec"]["selector"]["matchLabels"].items())
    pods = kjson(["kubectl","-n",ns,"get","pods","-l",sel,"-o","json"])["items"]
    lines = []
    for p in pods:
        name = p["metadata"]["name"]
        try:
            out = sh(["kubectl","-n",ns,"logs",name,"-c","falco","--since",since,"--timestamps"])
        except subprocess.CalledProcessError:
            out = sh(["kubectl","-n",ns,"logs",name,"--since",since,"--timestamps"])
        lines += out.splitlines()
    return lines

def get_talon_lines_all(ns, deploy, since):
    dep = kjson(["kubectl","-n",ns,"get","deploy",deploy,"-o","json"])
    sel = ",".join(f"{k}={v}" for k,v in dep["spec"]["selector"]["matchLabels"].items())
    pods = kjson(["kubectl","-n",ns,"get","pods","-l",sel,"-o","json"])["items"]
    lines = []
    for p in pods:
        name = p["metadata"]["name"]
        out = sh(["kubectl","-n",ns,"logs",name,"--since",since,"--timestamps"])
        lines += out.splitlines()
    return lines

def main():
    falco_lines = get_falco_lines_all(NAMESPACE, DS_NAME, SINCE)
    talon_lines = get_talon_lines_all(NAMESPACE, TALON_DEP, SINCE)
    if not falco_lines: print("[!] No Falco logs in window."); return
    if not talon_lines: print("[!] No Talon logs in window."); return

    # Falco: parse JSON after the kubectl timestamp
    falco_events = []  # (t_falco, rule)
    for l in falco_lines:
        jstart = l.find(" {")
        if jstart == -1: jstart = l.find("{")
        if jstart == -1: continue
        try:
            obj = json.loads(l[jstart:])
        except Exception:
            continue
        rule = obj.get("rule")
        tstr = obj.get("time")
        if not rule or not tstr: continue
        if ONLY_RULES and rule not in ONLY_RULES: continue
        try:
            tf = parse_falco_time(tstr)
        except Exception:
            continue
        falco_events.append((tf, rule))
    falco_events.sort(key=lambda x: x[0])
    if not falco_events:
        print("[!] No Falco events parsed (maybe ONLY_RULES filtered them out?)."); return

    # Talon: accept lines that look like action/notification; try to extract rule="..."
    rule_pat = re.compile(r'rule="([^"]+)"')
    talon_events = []  # (t_talon, rule_or_None, rawline)
    for l in talon_lines:
        if not any(k in l for k in TALON_ACTION_KEYWORDS):
            continue
        tt = parse_ts_prefix(l)
        if not tt: continue
        m = rule_pat.search(l)
        trule = m.group(1) if m else None
        talon_events.append((tt, trule, l))
    talon_events.sort(key=lambda x: x[0])
    if not talon_events:
        print("[!] No Talon action/notification lines parsed."); return

    # Correlate: prefer same-rule match; else take first Talon action after Falco within window
    pairs = []
    for tf, rule in falco_events:
        chosen = None
        # Try rule match first
        for tt, trule, line in talon_events:
            if trule != rule: 
                continue
            if tt < tf: 
                continue
            if MAX_LOOKAHEAD_SEC and (tt - tf).total_seconds() > MAX_LOOKAHEAD_SEC:
                break
            chosen = (tt, line, "rule-match")
            break
        # Fallback: any action after tf
        if not chosen:
            for tt, trule, line in talon_events:
                if tt < tf: 
                    continue
                if MAX_LOOKAHEAD_SEC and (tt - tf).total_seconds() > MAX_LOOKAHEAD_SEC:
                    break
                chosen = (tt, line, "time-only")
                break
        if chosen:
            dt = (chosen[0] - tf).total_seconds()
            pairs.append((tf, rule, chosen[0], dt, chosen[2]))

    if not pairs:
        print("[!] No Falco->Talon matches. Increase SINCE/MAX_LOOKAHEAD_SEC or run another attack."); return

    for tf, rule, tt, dt, mode in pairs:
        print(f"{tf.isoformat()}  {rule:40s} -> {tt.isoformat()}  MTTR={dt:.3f}s  [{mode}]")

    # --- save detailed events to CSV ---

    if not pairs:
        print("[!] No Falco->Talon matches. Increase SINCE/MAX_LOOKAHEAD_SEC, or check Talon action logs in the window.")
        with open("mttr_events.csv", "w", newline="") as f:
            csv.writer(f).writerow(["detected_at","rule","responded_at","mttr_seconds","correlation_mode"])
        sys.exit(0)

    for tf, rule, tt, dt, mode in pairs:
        print(f"{tf.isoformat()}  {rule:40s} -> {tt.isoformat()}  MTTR={dt:.3f}s  [{mode}]")

    # Save CSV for plotting
    with open("mttr_events.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["detected_at", "rule", "responded_at", "mttr_seconds", "correlation_mode"])
        for tf, rule, tt, dt, mode in pairs:
            w.writerow([tf.isoformat(), rule, tt.isoformat(), f"{dt:.6f}", mode])
    print("Wrote mttr_events.csv")

    vals = [p[3] for p in pairs]
    vals.sort()
    p90 = vals[max(0, int(0.9*len(vals))-1)]
    print("\nSUMMARY")
    print(f"count={len(vals)}  mean={statistics.mean(vals):.3f}s  median={statistics.median(vals):.3f}s  p90={p90:.3f}s  max={max(vals):.3f}s")



if __name__ == "__main__":
    main()
