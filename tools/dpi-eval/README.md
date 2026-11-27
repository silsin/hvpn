# DPI detectability harness

Measures how easily a passive observer could tell HVPN traffic from ordinary
traffic, using only packet sizes, directions and timing.

```
pip install numpy scikit-learn scapy
python dpi_eval.py --demo                      # pipeline check on synthetic data
python dpi_eval.py --tunnel tunnel.pcap --baseline normal.pcap --client-ip 192.168.1.5
```

## Capturing real traces (Windows, no Wireshark needed)

Run from an administrator PowerShell, on the same network for both captures:

```powershell
# 1. Normal traffic: browse / stream / download as you normally would for ~5 minutes
pktmon start --capture --pkt-size 0 -f normal.etl
# ... use the network ...
pktmon stop
pktmon etl2pcap normal.etl --out normal.pcap

# 2. Tunnel traffic: connect HVPN and do the same activities for ~5 minutes
pktmon start --capture --pkt-size 0 -f tunnel.etl
pktmon stop
pktmon etl2pcap tunnel.etl --out tunnel.pcap
```

Capture only the physical adapter. Capture HVPN's traffic to the server (UDP/TCP
on the server port), not the inner tunnel interface. Use `HVPN_TRANSPORT=quic`
and `HVPN_TRANSPORT=ws` in turn to test each transport.

## Reading the result

| Best AUC | Meaning |
|---|---|
| below 0.60 | hard to distinguish |
| 0.60 to 0.80 | partly detectable |
| above 0.80 | easily detectable; fix the top features listed |

The AUC is only meaningful with real captures, enough flows (dozens) and varied
activity. A low score here is not proof of safety against a real censor, who
also uses TLS fingerprints, active probing and IP reputation.
