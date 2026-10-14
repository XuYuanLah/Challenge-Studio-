#!/usr/bin/env python3
"""
Per-device baseline extraction from a pcap. Standard library only.

Produces exactly the baseline fields the project defines: destination
addresses and domains, protocols, ports, connection frequency, traffic volume,
duration, and DNS and TLS metadata.

    python3 analyse_pcap.py results/flat/hue-flat.pcap --json out.json
    python3 analyse_pcap.py results/*/hue-*.pcap --compare
"""

import argparse
import json
import os
import socket
import struct
import sys
from collections import Counter, defaultdict

PCAP_MAGICS = {
    0xA1B2C3D4: (">", 1e-6),   # big endian, microseconds
    0xD4C3B2A1: ("<", 1e-6),   # little endian, microseconds
    0xA1B23C4D: (">", 1e-9),   # nanoseconds
    0x4D3CB2A1: ("<", 1e-9),
}


def read_pcap(path):
    """Yield (timestamp, frame_bytes). Handles both endiannesses."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack(">I", hdr[:4])[0]
        if magic not in PCAP_MAGICS:
            magic = struct.unpack("<I", hdr[:4])[0]
            if magic not in PCAP_MAGICS:
                raise ValueError(f"{path}: not a pcap file "
                                 f"(try pcapng -> use `editcap -F pcap`)")
        endian, scale = PCAP_MAGICS[magic]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_sub, caplen, _ = struct.unpack(endian + "IIII", rec)
            data = f.read(caplen)
            if len(data) < caplen:
                return
            yield ts_sec + ts_sub * scale, data


def is_local(ip):
    o = ip.split(".")
    if len(o) != 4:
        return True
    try:
        a, b = int(o[0]), int(o[1])
    except ValueError:
        return True
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or a == 127 or (a == 169 and b == 254) or a >= 224 or a == 0)


def parse_qname(data, offset):
    labels = []
    i = offset
    guard = 0
    while i < len(data) and data[i] != 0 and guard < 64:
        n = data[i]
        if n & 0xC0:
            break
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
        guard += 1
    return ".".join(labels)


def sni_from_clienthello(payload):
    """Extract the SNI from a TLS ClientHello, if this is one."""
    try:
        if len(payload) < 45 or payload[0] != 0x16:
            return None, None
        ver = payload[1:3]
        body = payload[5:]
        if not body or body[0] != 0x01:
            return None, None
        hl = int.from_bytes(body[1:4], "big")
        b = body[4:4 + hl]
        i = 2 + 32
        i += 1 + b[i]                                   # session id
        i += 2 + int.from_bytes(b[i:i + 2], "big")      # cipher suites
        i += 1 + b[i]                                   # compression
        extlen = int.from_bytes(b[i:i + 2], "big")
        i += 2
        end = i + extlen
        sni = None
        offered = []
        while i + 4 <= end:
            et = int.from_bytes(b[i:i + 2], "big")
            el = int.from_bytes(b[i + 2:i + 4], "big")
            body_ext = b[i + 4:i + 4 + el]
            if et == 0 and sni is None:                 # server_name
                ln = int.from_bytes(body_ext[3:5], "big")
                sni = body_ext[5:5 + ln].decode("ascii", "ignore")
            elif et == 0x002b and len(body_ext) >= 1:   # supported_versions
                n = body_ext[0]
                for k in range(1, min(1 + n, len(body_ext)) - 1, 2):
                    offered.append(bytes(body_ext[k:k + 2]))
            i += 4 + el

        # A TLS 1.2 or 1.3 client still writes 0x0301 in legacy_version, so
        # reading that field alone reports "TLS 1.0" for a modern client. The
        # real maximum is in the supported_versions extension when present;
        # only fall back to legacy_version when it is absent, which is itself
        # the sign of a genuinely old client.
        vmap = {b"\x03\x00": "SSL3.0", b"\x03\x01": "TLS1.0",
                b"\x03\x02": "TLS1.1", b"\x03\x03": "TLS1.2",
                b"\x03\x04": "TLS1.3"}
        if offered:
            best = max((v for v in offered if v in vmap), default=None,
                       key=lambda v: list(vmap).index(v))
            version = vmap.get(best, "unknown") if best else "unknown"
        else:
            version = vmap.get(bytes(ver), "unknown") + " (legacy field)"
        return sni, version
    except Exception:
        return None, None


def analyse(path):
    first = last = None
    total_bytes = 0
    total_frames = 0

    by_host = defaultdict(lambda: {
        "frames": 0, "bytes_sent": 0, "bytes_recv": 0,
        "ext_bytes_sent": 0, "ext_bytes_recv": 0,
        "dns": Counter(), "sni": Counter(), "tls_versions": Counter(),
        "ext_dests": Counter(), "lan_dests": Counter(),
        "protocols": Counter(), "dst_ports": Counter(),
        "syns": [], "first": None, "last": None,
        "mdns": 0, "http_hosts": Counter(),
    })
    # (src,dst,sport,dport) -> [first_ts, last_ts, bytes]
    flows = {}
    vlan_ids = Counter()

    for ts, raw in read_pcap(path):
        total_frames += 1
        total_bytes += len(raw)
        if first is None:
            first = ts
        last = ts
        if len(raw) < 14:
            continue

        off = 12
        etype = struct.unpack(">H", raw[off:off + 2])[0]
        off += 2
        while etype in (0x8100, 0x88a8) and len(raw) >= off + 4:
            tci = struct.unpack(">H", raw[off:off + 2])[0]
            vlan_ids[tci & 0x0FFF] += 1
            etype = struct.unpack(">H", raw[off + 2:off + 4])[0]
            off += 4

        if etype != 0x0800 or len(raw) < off + 20:
            continue
        ihl = (raw[off] & 0x0F) * 4
        proto = raw[off + 9]
        sip = socket.inet_ntoa(raw[off + 12:off + 16])
        dip = socket.inet_ntoa(raw[off + 16:off + 20])
        l4 = off + ihl

        s = by_host[sip]
        s["frames"] += 1
        s["bytes_sent"] += len(raw)
        if s["first"] is None:
            s["first"] = ts
        s["last"] = ts
        by_host[dip]["bytes_recv"] += len(raw)
        if not is_local(dip):
            s["ext_bytes_sent"] += len(raw)
        if not is_local(sip):
            by_host[dip]["ext_bytes_recv"] += len(raw)

        sport = dport = None
        if proto == 6 and len(raw) >= l4 + 20:
            s["protocols"]["TCP"] += 1
            sport, dport = struct.unpack(">HH", raw[l4:l4 + 4])
            flags = raw[l4 + 13]
            doff = (raw[l4 + 12] >> 4) * 4
            payload = raw[l4 + doff:]
            if (flags & 0x12) == 0x02:      # SYN without ACK
                s["syns"].append((ts, dip, dport))
            key = (sip, dip, sport, dport)
            f = flows.get(key)
            if f is None:
                flows[key] = [ts, ts, len(raw), "TCP"]
            else:
                f[1] = ts
                f[2] += len(raw)
            if payload[:1] == b"\x16":
                sni, ver = sni_from_clienthello(payload)
                if sni:
                    s["sni"][sni] += 1
                    s["tls_versions"][ver] += 1
            elif dport == 80 and payload[:4] in (b"GET ", b"POST", b"PUT ",
                                                 b"HEAD"):
                text = payload[:400].decode("latin-1", "replace")
                for line in text.split("\r\n"):
                    if line.lower().startswith("host:"):
                        s["http_hosts"][line[5:].strip()] += 1
                        break
        elif proto == 17 and len(raw) >= l4 + 8:
            s["protocols"]["UDP"] += 1
            sport, dport = struct.unpack(">HH", raw[l4:l4 + 4])
            body = raw[l4 + 8:]
            if dport == 53 and len(body) > 12:
                s["dns"][parse_qname(body, 12).lower()] += 1
            if dport == 5353 or sport == 5353:
                s["mdns"] += 1
            key = (sip, dip, sport, dport)
            f = flows.get(key)
            if f is None:
                flows[key] = [ts, ts, len(raw), "UDP"]
            else:
                f[1] = ts
                f[2] += len(raw)
        elif proto == 1:
            s["protocols"]["ICMP"] += 1
        else:
            s["protocols"][f"ip-{proto}"] += 1

        if dport is not None:
            s["dst_ports"][dport] += 1
            pname = "TCP" if proto == 6 else "UDP"
            if is_local(dip):
                s["lan_dests"][(dip, pname, dport)] += 1
            else:
                s["ext_dests"][(dip, pname, dport)] += 1

    duration = (last - first) if (first and last) else 0.0

    # Per-host flow durations.
    host_flows = defaultdict(list)
    for (sip, dip, sp, dp), (f0, f1, nbytes, pn) in flows.items():
        host_flows[sip].append({
            "dst": dip, "proto": pn, "dport": dp,
            "duration_s": round(f1 - f0, 2), "bytes": nbytes,
            "external": not is_local(dip),
        })

    devices = {}
    for ip, d in by_host.items():
        if d["frames"] == 0:
            continue
        hours = max(duration / 3600.0, 1e-9)
        fl = host_flows.get(ip, [])
        ext_fl = [f for f in fl if f["external"]]
        syn_dests = Counter(f"{d2}:{p}" for _, d2, p in d["syns"])
        intervals = []
        syn_by_dest = defaultdict(list)
        for ts, d2, p in d["syns"]:
            syn_by_dest[f"{d2}:{p}"].append(ts)
        for dest, tss in syn_by_dest.items():
            tss.sort()
            gaps = [round(tss[i + 1] - tss[i], 1)
                    for i in range(len(tss) - 1)]
            if gaps:
                g = sorted(gaps)
                intervals.append({
                    "dest": dest, "connections": len(tss),
                    "median_interval_s": g[len(g) // 2],
                    "min_interval_s": g[0], "max_interval_s": g[-1],
                })
        devices[ip] = {
            "frames": d["frames"],
            "bytes_sent": d["bytes_sent"],
            "bytes_recv": d["bytes_recv"],
            "mb_per_hour_sent": round(d["bytes_sent"] / 1e6 / hours, 4),
            "external_bytes_sent": d["ext_bytes_sent"],
            "external_bytes_recv": d["ext_bytes_recv"],
            "protocols": dict(d["protocols"]),
            "top_dst_ports": d["dst_ports"].most_common(10),
            "dns_names": d["dns"].most_common(20),
            "distinct_dns_names": len(d["dns"]),
            "tls_sni": d["sni"].most_common(20),
            "tls_versions": dict(d["tls_versions"]),
            "http_cleartext_hosts": d["http_hosts"].most_common(10),
            "external_destinations": [
                {"dst": k[0], "proto": k[1], "port": k[2], "packets": v}
                for k, v in d["ext_dests"].most_common(20)],
            "distinct_external_destinations": len(d["ext_dests"]),
            "lan_destinations": [
                {"dst": k[0], "proto": k[1], "port": k[2], "packets": v}
                for k, v in d["lan_dests"].most_common(20)],
            "distinct_lan_destinations": len(d["lan_dests"]),
            "new_connections": len(d["syns"]),
            "connection_frequency": intervals,
            "mdns_frames": d["mdns"],
            "longest_external_flow_s": round(
                max([f["duration_s"] for f in ext_fl], default=0.0), 1),
            "external_flow_count": len(ext_fl),
        }

    return {
        "file": os.path.basename(path),
        "frames": total_frames,
        "bytes": total_bytes,
        "duration_s": round(duration, 2),
        "vlan_ids_seen": dict(vlan_ids),
        "devices": devices,
    }


def rescale(r, speed):
    """Convert compressed lab time back to real-world equivalents.

    Running at --speed 120 makes a 600s report interval appear as 5s. The
    shapes are right but the numbers need multiplying back before they are
    compared with a real baseline.
    """
    r["speed"] = speed
    r["real_equivalent_duration_s"] = round(r["duration_s"] * speed, 1)
    for d in r["devices"].values():
        # Volume per hour needs NO rescaling. Compressing time by N shrinks
        # both the bytes sent and the elapsed time by N, so the rate is
        # already the real-world rate. Only the time-valued figures below are
        # compressed and need multiplying back.
        d["longest_external_flow_s"] = round(
            d["longest_external_flow_s"] * speed, 1)
        for iv in d["connection_frequency"]:
            for k in ("median_interval_s", "min_interval_s", "max_interval_s"):
                iv[k] = round(iv[k] * speed, 1)


def print_report(r, top=8):
    print(f"\n=== {r['file']}")
    print(f"frames={r['frames']} bytes={r['bytes']/1e6:.2f} MB "
          f"duration={r['duration_s']/60:.1f} min")
    if r.get("speed", 1.0) != 1.0:
        print(f"ran at --speed {r['speed']}: figures below are rescaled to "
              f"real-world equivalents "
              f"({r['real_equivalent_duration_s']/3600:.1f} h of device time)")
    if r["vlan_ids_seen"]:
        print(f"VLAN ids on this link: {r['vlan_ids_seen']}")
    ranked = sorted(r["devices"].items(),
                    key=lambda kv: -kv[1]["bytes_sent"])[:top]
    for ip, d in ranked:
        print(f"\n  {ip}")
        print(f"      sent {d['bytes_sent']/1e6:.3f} MB "
              f"({d['mb_per_hour_sent']} MB/h), "
              f"external {d['external_bytes_sent']/1e3:.1f} kB")
        print(f"      protocols {d['protocols']}  mDNS frames {d['mdns_frames']}")
        if d["dns_names"]:
            print(f"      DNS ({d['distinct_dns_names']} distinct): "
                  f"{', '.join(n for n, _ in d['dns_names'][:6])}")
        if d["tls_sni"]:
            print(f"      TLS SNI: {', '.join(n for n, _ in d['tls_sni'][:6])}"
                  f"  versions {d['tls_versions']}")
        if d["http_cleartext_hosts"]:
            print(f"      cleartext HTTP to: "
                  f"{', '.join(h for h, _ in d['http_cleartext_hosts'])}")
        if d["external_destinations"]:
            print(f"      external dests ({d['distinct_external_destinations']}):")
            for e in d["external_destinations"][:4]:
                print(f"         {e['dst']} {e['proto']}/{e['port']} "
                      f"pkts={e['packets']}")
        print(f"      LAN destinations: {d['distinct_lan_destinations']} "
              f"distinct, new connections: {d['new_connections']}, "
              f"longest external flow: {d['longest_external_flow_s']}s")
        for iv in d["connection_frequency"][:3]:
            print(f"      reconnects to {iv['dest']}: n={iv['connections']} "
                  f"median {iv['median_interval_s']}s "
                  f"(min {iv['min_interval_s']}, max {iv['max_interval_s']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--json", default="")
    ap.add_argument("--compare", action="store_true",
                    help="print a side-by-side of the headline numbers")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--speed", type=float, default=1.0,
                    help="the --speed the devices ran at, so intervals are "
                         "reported as their real-world equivalent")
    args = ap.parse_args()

    out = []
    for p in args.pcaps:
        if not os.path.exists(p):
            print(f"missing: {p}", file=sys.stderr)
            continue
        try:
            r = analyse(p)
            if args.speed != 1.0:
                rescale(r, args.speed)
        except ValueError as e:
            print(e, file=sys.stderr)
            continue
        out.append(r)
        if not args.compare:
            print_report(r, args.top)

    if args.compare and len(out) >= 2:
        print(f"\n{'file':<34}{'frames':>9}{'MB':>9}{'devices':>9}"
              f"{'VLANs':>9}{'ext dests':>11}")
        for r in out:
            ext = sum(d["distinct_external_destinations"]
                      for d in r["devices"].values())
            print(f"{r['file']:<34}{r['frames']:>9}"
                  f"{r['bytes']/1e6:>9.2f}{len(r['devices']):>9}"
                  f"{len(r['vlan_ids_seen']):>9}{ext:>11}")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(out if len(out) > 1 else out[0], f, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
