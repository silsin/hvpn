#!/usr/bin/env python3
"""HVPN DPI-detectability harness.

Trains a classifier to tell HVPN tunnel traffic from ordinary traffic using only
what a passive censor can see (packet sizes, directions, timing). If a simple
model separates them easily, a real censor's model can too, and the report
shows which features give the tunnel away so you can fix them.

Usage
  python dpi_eval.py --demo
  python dpi_eval.py --tunnel tunnel.pcap --baseline normal.pcap [--client-ip 192.168.1.5]
  python dpi_eval.py --tunnel-csv t.csv --baseline-csv b.csv        # flow,ts,size,dir

The demo uses SYNTHETIC traffic only to check the pipeline works. Its numbers say
nothing about a real censor; capture real traces (see README.md) for that.
"""
import argparse
import math
import sys
from collections import defaultdict

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold, cross_val_predict

WINDOW = 100  # packets per sample
MIN_FLOW = 50  # ignore flows shorter than this
# A flow is a list of (timestamp, size, direction) with direction +1 = client->server.


# ----------------------------------------------------------------- loading ---
def flows_from_pcap(path, client_ip=None):
    from scapy.all import IP, IPv6, TCP, UDP, PcapReader  # imported lazily

    raw = defaultdict(list)
    with PcapReader(path) as rd:
        for pkt in rd:
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                continue
            if TCP in pkt:
                l4, proto = pkt[TCP], "tcp"
            elif UDP in pkt:
                l4, proto = pkt[UDP], "udp"
            else:
                continue
            size = len(bytes(l4.payload))
            if size == 0:  # pure ACKs carry no application signal
                continue
            a, b = (ip.src, l4.sport), (ip.dst, l4.dport)
            key = (proto,) + tuple(sorted([a, b]))
            raw[key].append((float(pkt.time), size, a, b))
    flows = []
    for key, pkts in raw.items():
        pkts.sort(key=lambda p: p[0])
        src0 = pkts[0][2]
        if client_ip:
            client = next((p[2] for p in pkts if p[2][0] == client_ip), src0)
        else:
            client = src0
        flows.append([(t, s, 1 if a == client else -1) for t, s, a, _ in pkts])
    return flows


def flows_from_csv(path):
    raw = defaultdict(list)
    with open(path) as f:
        next(f)
        for line in f:
            fl, ts, size, d = line.strip().split(",")
            raw[fl].append((float(ts), int(size), int(d)))
    return [sorted(v) for v in raw.values()]


# ---------------------------------------------------------------- features ---
def entropy(counts):
    tot = counts.sum()
    if tot == 0:
        return 0.0
    p = counts[counts > 0] / tot
    return float(-(p * np.log2(p)).sum())


def window_features(w):
    """Feature vector + names for one window of packets."""
    t = np.array([p[0] for p in w])
    s = np.array([p[1] for p in w], dtype=float)
    d = np.array([p[2] for p in w])
    iat = np.diff(t) if len(t) > 1 else np.zeros(1)
    feats, names = [], []

    def add(n, v):
        names.append(n)
        feats.append(float(v))

    for label, mask in (("up", d > 0), ("down", d < 0), ("all", np.ones_like(d, bool))):
        x = s[mask]
        if len(x) == 0:
            x = np.zeros(1)
        add(f"size_mean_{label}", x.mean())
        add(f"size_std_{label}", x.std())
        add(f"size_min_{label}", x.min())
        add(f"size_max_{label}", x.max())
        for q in (10, 50, 90):
            add(f"size_p{q}_{label}", np.percentile(x, q))
    add("frac_up", (d > 0).mean())
    add("frac_small_lt100", (s < 100).mean())
    add("frac_at_max", (s >= s.max() - 2).mean())  # pile-up at one MTU-like size
    add("distinct_sizes", len(set(s.astype(int))) / len(s))
    hist, _ = np.histogram(s, bins=24, range=(0, 1500))
    add("size_entropy", entropy(hist))
    for i, h in enumerate(hist):
        add(f"hist_{i}", h / len(s))
    add("iat_mean", iat.mean())
    add("iat_std", iat.std())
    add("iat_p50", np.percentile(iat, 50))
    add("iat_p90", np.percentile(iat, 90))
    add("iat_cv", iat.std() / (iat.mean() + 1e-9))
    add("dir_switches", (np.diff(d) != 0).mean() if len(d) > 1 else 0)
    # run lengths of same-direction packets (burstiness)
    runs, cur = [], 1
    for i in range(1, len(d)):
        if d[i] == d[i - 1]:
            cur += 1
        else:
            runs.append(cur)
            cur = 1
    runs.append(cur)
    add("run_mean", np.mean(runs))
    add("run_max", np.max(runs))
    for i in range(10):  # first packets: handshake shape
        add(f"first_{i}", d[i] * s[i] if i < len(s) else 0)
    return feats, names


def build_dataset(flows_by_label):
    X, y, g, names = [], [], [], None
    gid = 0
    for label, flows in flows_by_label.items():
        for fl in flows:
            if len(fl) < MIN_FLOW:
                continue
            gid += 1
            for i in range(0, len(fl) - WINDOW + 1, WINDOW // 2):
                f, names = window_features(fl[i : i + WINDOW])
                X.append(f)
                y.append(label)
                g.append(gid)
            if len(fl) < WINDOW:
                f, names = window_features(fl)
                X.append(f)
                y.append(label)
                g.append(gid)
    return np.array(X), np.array(y), np.array(g), names


# -------------------------------------------------------------------- demo ---
def demo_flows(rng, n_flows=40, pkts=400):
    """Synthetic stand-ins. Tunnel sizes follow HVPN's real framing."""
    OVERHEAD = 20 + 16 + 2 + 35  # frame hdr + AEAD tag + pad prefix + QUIC (approx.)

    def inner_size():
        r = rng.random()
        if r < 0.40:
            return 52  # TCP ACKs inside the tunnel
        if r < 0.55:
            return int(rng.integers(60, 400))
        return int(min(1200, rng.normal(1100, 200)))  # tunnel MTU is 1200

    tunnel, base = [], []
    for _ in range(n_flows):  # HVPN: every inner packet becomes one datagram
        t, fl = 0.0, []
        for _ in range(pkts):
            t += rng.exponential(0.004)
            fl.append((t, inner_size() + OVERHEAD + int(rng.integers(0, 17)),
                       1 if rng.random() < 0.4 else -1))
        tunnel.append(fl)
    for _ in range(n_flows):  # HTTP/3-like page loads and downloads
        t, fl = 0.0, []
        for _ in range(pkts):
            t += rng.exponential(0.006)
            if rng.random() < 0.30:
                fl.append((t, int(rng.integers(30, 120)), 1))  # small ACK / request
            else:
                fl.append((t, 1252 if rng.random() < 0.85 else int(rng.integers(200, 1252)), -1))
        base.append(fl)
    return {"tunnel": tunnel, "baseline": base}


# ------------------------------------------------------------------ report ---
def evaluate(X, y, g, names):
    labels = (y == "tunnel").astype(int)
    n_groups = len(set(g))
    if n_groups < 4 or labels.min() == labels.max():
        sys.exit("Need at least a few flows of BOTH classes (>=50 packets each).")
    cv = GroupKFold(n_splits=min(5, n_groups))
    results = {}
    for name, model in (
        ("RandomForest", RandomForestClassifier(300, random_state=0, n_jobs=-1)),
        ("GradientBoosting", GradientBoostingClassifier(random_state=0)),
    ):
        prob = cross_val_predict(model, X, labels, groups=g, cv=cv, method="predict_proba")[:, 1]
        pred = (prob > 0.5).astype(int)
        results[name] = (roc_auc_score(labels, prob), (pred == labels).mean(),
                         confusion_matrix(labels, pred))
    rf = RandomForestClassifier(300, random_state=0, n_jobs=-1).fit(X, labels)
    imp = sorted(zip(rf.feature_importances_, names), reverse=True)[:8]
    return results, imp


def verdict(auc):
    if auc < 0.60:
        return "HARD to distinguish (good). Re-test with more and more varied traces."
    if auc < 0.80:
        return "PARTLY detectable. A determined censor could flag a share of flows."
    return "EASILY detectable. Fix the leading features below before relying on this."


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--tunnel"); ap.add_argument("--baseline")
    ap.add_argument("--tunnel-csv"); ap.add_argument("--baseline-csv")
    ap.add_argument("--client-ip")
    a = ap.parse_args()

    if a.demo:
        print("DEMO MODE: synthetic traffic, pipeline check only.\n")
        data = demo_flows(np.random.default_rng(1))
    elif (a.tunnel and a.baseline) or (a.tunnel_csv and a.baseline_csv):
        if a.tunnel:
            data = {"tunnel": flows_from_pcap(a.tunnel, a.client_ip),
                    "baseline": flows_from_pcap(a.baseline, a.client_ip)}
        else:
            data = {"tunnel": flows_from_csv(a.tunnel_csv),
                    "baseline": flows_from_csv(a.baseline_csv)}
    else:
        ap.error("give --demo, or --tunnel and --baseline (pcap), or the CSV pair")

    X, y, g, names = build_dataset(data)
    print(f"{len(X)} windows from {len(set(g))} flows "
          f"({(y == 'tunnel').sum()} tunnel / {(y == 'baseline').sum()} baseline)\n")
    results, imp = evaluate(X, y, g, names)
    for name, (auc, acc, cm) in results.items():
        print(f"{name:17s} AUC={auc:.3f}  accuracy={acc:.3f}  "
              f"[TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}]")
    best = max(r[0] for r in results.values())
    print(f"\nBest AUC {best:.3f}: {verdict(best)}")
    print("\nFeatures that give the tunnel away (most important first):")
    for w, n in imp:
        print(f"  {w:.3f}  {n}")


if __name__ == "__main__":
    main()
