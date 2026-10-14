#!/usr/bin/env python3
"""
Run the before/after experiment: build each state, let the devices settle,
capture, probe exposure from an IoT device, tear down, then compare.

    sudo python3 run_experiment.py --speed 60 --settle 60 --listen 30

One variable group changes between states (IoT VLAN and subnet, plus the
firewall policy), so differences in the output are attributable.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mininet.log import setLogLevel

import iot_lab
from lab import config as C

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


def run_state(mode, args):
    print(f"\n{'='*70}\n=== STATE: {mode}\n{'='*70}")
    logdir = os.path.abspath(os.path.join(args.logdir, mode))
    os.makedirs(logdir, exist_ok=True)

    os.system("mn -c >/dev/null 2>&1")
    net, hosts, r1, cloud = iot_lab.build(mode, args.datapath, args.trunk)
    try:
        if args.capture:
            iot_lab.start_capture(hosts, r1, mode, logdir)
        iot_lab.start_services(hosts, r1, cloud, mode, args.speed, logdir,
                               quiet=True)

        print(f"*** letting devices run for {args.settle:.0f}s")
        time.sleep(args.settle)

        # Probe from an IoT device: the perspective that matters.
        for probe_host in args.probe_from.split(","):
            probe_host = probe_host.strip()
            if not probe_host:
                continue
            out = os.path.join(logdir, f"recon-{probe_host}.json")
            print(f"*** probing exposure from {probe_host} "
                  f"({args.listen:.0f}s passive)")
            res = hosts[probe_host].cmd(
                f"{PY} {os.path.join(HERE, 'recon.py')} --mode {mode} "
                f"--listen {args.listen} --label {probe_host} --out {out} "
                f"2>&1")
            tail = [l for l in res.strip().splitlines() if l.strip()]
            print("    " + "\n    ".join(tail[-12:]))

        # Firewall counters are evidence in their own right.
        fw = r1.cmd("iptables -L FORWARD -n -v")
        with open(os.path.join(logdir, "iptables-forward.txt"), "w") as f:
            f.write(fw)
        inp = r1.cmd("iptables -L INPUT -n -v")
        with open(os.path.join(logdir, "iptables-input.txt"), "w") as f:
            f.write(inp)

        if args.capture:
            time.sleep(2)
    finally:
        iot_lab.stop_all(net, hosts, r1, cloud)
        net.stop()
    return logdir


def load(logdir, host):
    p = os.path.join(logdir, f"recon-{host}.json")
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def compare(args, states):
    host = args.probe_from.split(",")[0].strip()
    data = {}
    for mode in states:
        d = load(os.path.abspath(os.path.join(args.logdir, mode)), host)
        if d:
            data[mode] = d
    if len(data) < 2:
        print("\nnot enough results to compare")
        return

    print(f"\n{'='*70}")
    print(f"=== EXPOSURE COMPARISON, measured from '{host}'")
    print(f"{'='*70}\n")

    rows = [
        ("hosts answering at all (incl. ping)", "hosts_reachable"),
        ("main-LAN hosts answering", "main_lan_hosts_reachable"),
        ("main-LAN TCP services reachable", "main_lan_tcp_services_reachable"),

        ("open TCP ports found in total", "total_open_tcp_ports"),
        ("devices visible passively (src MACs)", "devices_visible_passively"),
        ("main-LAN hosts visible passively", "main_lan_hosts_visible"),
        ("main-LAN hosts broadcasting to it", "main_lan_broadcasters_visible"),
        ("main-LAN broadcast frames received", "main_lan_broadcast_frames"),
        ("mDNS service types exposed", "mdns_service_types"),
    ]
    width = max(len(label) for label, _ in rows) + 2
    header = "".join(f"{m:>14s}" for m in data)
    print(" " * width + header)
    for label, key in rows:
        line = f"{label:<{width}}"
        for mode in data:
            line += f"{data[mode]['summary'][key]:>14}"
        print(line)

    line = f"{'router TCP ports reachable':<{width}}"
    for mode in data:
        ports = data[mode]["summary"]["router_ports_reachable"]
        line += f"{(','.join(map(str, ports)) or 'none'):>14}"
    print(line)

    print()
    for mode in data:
        p = data[mode]["passive"]
        print(f"  {mode}: VLAN ids seen on the link "
              f"{p['vlan_ids_seen'] or '{}'}; subnets "
              f"{list(p['subnets_seen'])}")

    out = os.path.join(args.logdir, "comparison.json")
    with open(out, "w") as f:
        json.dump({m: data[m]["summary"] for m in data}, f, indent=2)
    print(f"\nwrote {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--states", default="flat,segmented,hardened")
    ap.add_argument("--speed", type=float, default=60.0,
                    help="device time compression (60 = 24h in 24min)")
    ap.add_argument("--settle", type=float, default=60.0,
                    help="seconds of device traffic before probing")
    ap.add_argument("--listen", type=float, default=30.0,
                    help="seconds of passive listening in the prober")
    ap.add_argument("--probe-from", default="iotcam,iotsens")
    ap.add_argument("--datapath", choices=["kernel", "user"], default="kernel")
    ap.add_argument("--trunk", action="store_true")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--logdir", default="results")
    args = ap.parse_args()

    setLogLevel("warning")
    states = [s.strip() for s in args.states.split(",") if s.strip()]
    for mode in states:
        run_state(mode, args)
    compare(args, states)


if __name__ == "__main__":
    main()
