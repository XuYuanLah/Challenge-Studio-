#!/usr/bin/env python3
"""
Exposure prober. Run it ON a device to measure what that device can see and
reach. This is what produces the before/after segmentation numbers.

Two halves:

  active   ICMP sweep plus TCP connect to a port list. Answers "what can this
           device reach?"
  passive  Listen on the interface for a while and count what arrives without
           being asked for. Answers "what can this device see?" - which is the
           half that matters for a device with no credentials.

  python3 recon.py --out results/flat/recon-hue.json --listen 30

Scope: only sweeps the lab's own subnets. It is an active scan, so point it at
a lab you own.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import config as C  # noqa: E402

ETH_P_ALL = 3


# --------------------------------------------------------------------------
# active
# --------------------------------------------------------------------------

def ping(ip, timeout=1):
    r = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def tcp_open(ip, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def detect_dns_redirect(timeout=1.0):
    """Is a DNS-redirect rule answering on behalf of every address?

    A hardened router DNATs all port-53 traffic to the resolver, which makes
    TCP 53 look open on every host in the subnet. Probing an address that is
    certainly not in use settles it: if that connects, port 53 results tell
    you about the router's rule, not about the hosts.
    """
    decoys = ["192.168.0.250", "192.168.0.251", "192.168.107.30"]
    for ip in decoys:
        if tcp_open(ip, 53, timeout):
            return True, ip
    return False, None


def active_scan(mode, ports, include_router=True, workers=64, timeout=1.0):
    """Sweep the lab's known hosts in every subnet, plus the gateways.

    Probes run in a thread pool: a dropped port costs the full timeout, and
    serially that turns a few hundred probes into several minutes.
    """
    from concurrent.futures import ThreadPoolExecutor

    targets = [(n.name, n.ip(mode), n.role) for n in C.NODES]
    if include_router:
        for label, ip in (("router-main", C.GW_MAIN),
                          ("router-iot", C.GW_IOT)):
            targets.append((label, ip, "router"))
    targets.append(("cloud", C.CLOUD_IP, "wan"))

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as ex:
        alive_map = dict(zip(
            [t[0] for t in targets],
            ex.map(lambda t: ping(t[1], int(timeout)), targets)))

    jobs = [(name, ip, role, p) for name, ip, role in targets for p in ports]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(
            lambda j: (j[0], j[3], tcp_open(j[1], j[3], timeout)), jobs))

    open_map = {}
    for name, port, is_open in results:
        if is_open:
            open_map.setdefault(name, []).append(port)

    dns_redirect, decoy = detect_dns_redirect(timeout)

    reachable = {}
    for name, ip, role in targets:
        open_ports = sorted(open_map.get(name, []))
        if not (alive_map.get(name) or open_ports):
            continue
        entry = {"ip": ip, "role": role,
                 "ping": bool(alive_map.get(name)),
                 "open_tcp": open_ports}
        # With a DNS redirect in force, a port-53 hit is the router's rule
        # answering, not a service on this host. The resolver itself is the
        # one host where 53 is genuinely open. The same class of artefact
        # produced two misleading negatives in the physical lab's nmap runs.
        if dns_redirect and 53 in open_ports and ip != C.RESOLVER_IP:
            entry["dns_redirect_artefact"] = True
            entry["real_open_tcp"] = [p for p in open_ports if p != 53]
            if not entry["real_open_tcp"] and not entry["ping"]:
                entry["redirect_suspected"] = True
        reachable[name] = entry

    return {"hosts": reachable, "dns_redirect_active": dns_redirect,
            "dns_redirect_decoy": decoy}


# --------------------------------------------------------------------------
# passive
# --------------------------------------------------------------------------

def subnet_of(ip):
    o = ip.split(".")
    if len(o) != 4:
        return None
    return f"{o[0]}.{o[1]}.{o[2]}.0/24"


def parse_mdns_services(payload):
    """Pull service types out of an mDNS message, cheaply."""
    out = set()
    try:
        i = 12
        # Walk labels looking for the _svc._proto.local shape.
        text = payload[12:]
        chunks = []
        cur = []
        j = 0
        while j < len(text) and len(chunks) < 400:
            n = text[j]
            if n == 0:
                if cur:
                    chunks.append(".".join(cur))
                cur = []
                j += 1
                continue
            if n & 0xC0:
                j += 2
                if cur:
                    chunks.append(".".join(cur))
                cur = []
                continue
            label = text[j + 1:j + 1 + n]
            try:
                cur.append(label.decode("ascii"))
            except Exception:
                cur = []
                j += n + 1
                continue
            j += n + 1
        for c in chunks:
            parts = c.split(".")
            for k in range(len(parts) - 1):
                if parts[k].startswith("_") and parts[k + 1] in ("_tcp", "_udp"):
                    out.add(f"{parts[k]}.{parts[k+1]}")
    except Exception:
        pass
    return out


SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4


def passive_listen(iface, seconds, my_ip, main_ips=frozenset(),
                   wan_prefix="203.0.113."):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    s.settimeout(1.0)
    # The kernel strips the 802.1Q tag before handing the frame to AF_PACKET,
    # so a VLAN tag is invisible unless we ask for the auxiliary data that
    # carries it. This is why tcpdump shows a tag here and a naive raw socket
    # does not.
    aux_ok = True
    try:
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    except OSError:
        aux_ok = False

    stats = {
        "frames": 0,
        "bytes": 0,
        "src_macs": Counter(),
        "src_ips": Counter(),
        "subnets": Counter(),
        "vlan_tagged": 0,
        "vlan_ids": Counter(),
        "mdns_frames": 0,
        "mdns_services": Counter(),
        "broadcast": 0,
        "multicast": 0,
        "foreign_subnet_frames": 0,
        "foreign_bcast_frames": 0,
        "foreign_bcast_sources": Counter(),
        "main_lan_srcs": Counter(),
        "main_lan_bcast_frames": 0,
        "main_lan_bcast_srcs": Counter(),
        "protocols": Counter(),
        "dst_ports": Counter(),
    }
    my_subnet = subnet_of(my_ip)
    stats["vlan_from_auxdata"] = 0
    deadline = time.time() + seconds
    while time.time() < deadline:
        aux_vlan = None
        try:
            if aux_ok:
                raw, anc, _flags, _addr = s.recvmsg(65535, 1024)
                for level, ctype, data in anc:
                    if (level == SOL_PACKET and ctype == PACKET_AUXDATA
                            and len(data) >= 20):
                        (tp_status, _len, _snap, _mac, _net,
                         tci, _tpid) = struct.unpack("=IIIHHHH", data[:20])
                        if tp_status & TP_STATUS_VLAN_VALID:
                            aux_vlan = tci & 0x0FFF
            else:
                raw = s.recv(65535)
        except socket.timeout:
            continue
        except Exception:
            break
        if aux_vlan is not None:
            stats["vlan_tagged"] += 1
            stats["vlan_ids"][aux_vlan] += 1
            stats["vlan_from_auxdata"] += 1
        stats["frames"] += 1
        stats["bytes"] += len(raw)
        if len(raw) < 14:
            continue
        dst_mac = raw[0:6]
        src_mac = ":".join("%02x" % b for b in raw[6:12])
        stats["src_macs"][src_mac] += 1
        is_bcast = dst_mac == b"\xff" * 6
        is_mcast = bool(dst_mac[0] & 1) and not is_bcast
        if is_bcast:
            stats["broadcast"] += 1
        elif is_mcast:
            stats["multicast"] += 1

        off = 12
        etype = struct.unpack(">H", raw[off:off + 2])[0]
        off += 2
        while etype in (0x8100, 0x88a8) and len(raw) >= off + 4:
            tci = struct.unpack(">H", raw[off:off + 2])[0]
            stats["vlan_tagged"] += 1
            stats["vlan_ids"][tci & 0x0FFF] += 1
            etype = struct.unpack(">H", raw[off + 2:off + 4])[0]
            off += 4

        if etype == 0x0806:
            stats["protocols"]["ARP"] += 1
            continue
        if etype != 0x0800 or len(raw) < off + 20:
            stats["protocols"][hex(etype)] += 1
            continue

        ihl = (raw[off] & 0x0F) * 4
        proto = raw[off + 9]
        src_ip = socket.inet_ntoa(raw[off + 12:off + 16])
        stats["src_ips"][src_ip] += 1
        sn = subnet_of(src_ip)
        if sn:
            stats["subnets"][sn] += 1
            # Count only frames from another *internal* segment. The device's
            # own traffic to and from the internet is legitimate and would
            # otherwise swamp the number this metric exists to show.
            # Traffic from a main-LAN host. In the flat state these arrive
            # directly because everything shares one broadcast domain; once
            # segmented, only what the router forwards should get through.
            if src_ip in main_ips:
                stats["main_lan_srcs"][src_ip] += 1
                if is_bcast or is_mcast:
                    stats["main_lan_bcast_frames"] += 1
                    stats["main_lan_bcast_srcs"][src_ip] += 1

            foreign = (my_subnet and sn != my_subnet
                       and not src_ip.startswith("224.")
                       and not src_ip.startswith(wan_prefix))
            if foreign:
                stats["foreign_subnet_frames"] += 1
                # Broadcast and multicast from another segment is the
                # interesting case: nothing asked for it, so it is genuine
                # layer-2 leakage rather than a routed reply. Routed unicast
                # from a controller is expected and should not be counted as
                # exposure.
                if is_bcast or is_mcast:
                    stats["foreign_bcast_frames"] += 1
                    stats["foreign_bcast_sources"][src_ip] += 1

        l4 = off + ihl
        if proto == 17 and len(raw) >= l4 + 8:
            stats["protocols"]["UDP"] += 1
            sport, dport = struct.unpack(">HH", raw[l4:l4 + 4])
            stats["dst_ports"][dport] += 1
            if dport == 5353 or sport == 5353:
                stats["mdns_frames"] += 1
                for svc in parse_mdns_services(raw[l4 + 8:]):
                    stats["mdns_services"][svc] += 1
        elif proto == 6 and len(raw) >= l4 + 4:
            stats["protocols"]["TCP"] += 1
            stats["dst_ports"][struct.unpack(">H", raw[l4 + 2:l4 + 4])[0]] += 1
        elif proto == 1:
            stats["protocols"]["ICMP"] += 1
        else:
            stats["protocols"][f"ip-proto-{proto}"] += 1
    s.close()
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="flat")
    ap.add_argument("--iface", default="")
    ap.add_argument("--my-ip", default="")
    ap.add_argument("--listen", type=float, default=30.0,
                    help="seconds of passive listening")
    ap.add_argument("--no-active", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    iface = args.iface
    if not iface:
        # first non-loopback interface
        for name in sorted(os.listdir("/sys/class/net")):
            if name != "lo":
                iface = name
                break
    my_ip = args.my_ip
    if not my_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("203.0.113.1", 9))
            my_ip = s.getsockname()[0]
        except Exception:
            my_ip = "0.0.0.0"
        finally:
            s.close()

    result = {"label": args.label, "mode": args.mode, "iface": iface,
              "my_ip": my_ip, "listen_seconds": args.listen,
              "ts": round(time.time(), 3)}

    # Passive first, deliberately. The active scan generates replies from all
    # over the lab, and if it ran first those replies would be counted as
    # things this device "could see" without asking.
    main_ips = C.ips_for_role("main", args.mode)
    p = passive_listen(iface, args.listen, my_ip, main_ips)

    if not args.no_active:
        scan = active_scan(args.mode, C.PROBE_PORTS)
        result["reachable"] = scan["hosts"]
        result["dns_redirect_active"] = scan["dns_redirect_active"]
        result["dns_redirect_decoy"] = scan["dns_redirect_decoy"]

    result["passive"] = {
        "frames": p["frames"],
        "bytes": p["bytes"],
        "distinct_src_macs": len(p["src_macs"]),
        "distinct_src_ips": len(p["src_ips"]),
        "src_macs": p["src_macs"].most_common(40),
        "src_ips": p["src_ips"].most_common(40),
        "subnets_seen": dict(p["subnets"]),
        "foreign_subnet_frames": p["foreign_subnet_frames"],
        "foreign_segment_broadcast_frames": p["foreign_bcast_frames"],
        "foreign_segment_broadcast_sources": p["foreign_bcast_sources"].most_common(10),
        "main_lan_hosts_seen": sorted(p["main_lan_srcs"]),
        "main_lan_hosts_seen_count": len(p["main_lan_srcs"]),
        "main_lan_broadcast_frames": p["main_lan_bcast_frames"],
        "main_lan_broadcasters": sorted(p["main_lan_bcast_srcs"]),
        "main_lan_broadcasters_count": len(p["main_lan_bcast_srcs"]),
        "vlan_tagged_frames": p["vlan_tagged"],
        "vlan_ids_seen": dict(p["vlan_ids"]),
        "broadcast_frames": p["broadcast"],
        "multicast_frames": p["multicast"],
        "mdns_frames": p["mdns_frames"],
        "mdns_service_types": sorted(p["mdns_services"]),
        "mdns_service_type_count": len(p["mdns_services"]),
        "protocols": dict(p["protocols"]),
        "top_dst_ports": p["dst_ports"].most_common(15),
    }

    # Headline numbers, the ones that go in the comparison.
    r = result.get("reachable", {})
    def real_ports(v):
        """Open ports with router-side artefacts removed."""
        if v.get("redirect_suspected"):
            return []
        if v.get("dns_redirect_artefact"):
            return v.get("real_open_tcp", [])
        return v["open_tcp"]

    result["summary"] = {
        "hosts_reachable": len(r),
        "main_lan_hosts_reachable": sum(
            1 for v in r.values() if v["role"] == "main"),

        # The metric that should go to zero: services on the main LAN that an
        # IoT device can actually open a TCP connection to.
        "main_lan_tcp_services_reachable": sum(
            len(real_ports(v)) for v in r.values() if v["role"] == "main"),
        "router_ports_reachable": sorted(
            {p for k, v in r.items() if v["role"] == "router"
             for p in real_ports(v)}),
        "total_open_tcp_ports": sum(len(real_ports(v)) for v in r.values()),
        "devices_visible_passively": result["passive"]["distinct_src_macs"],
        "foreign_subnet_frames": result["passive"]["foreign_subnet_frames"],
        "leaked_broadcast_frames":
            result["passive"]["foreign_segment_broadcast_frames"],
        # The generic exposure measure: how much of the main LAN this device
        # can see without asking for any of it.
        "main_lan_hosts_visible": result["passive"]["main_lan_hosts_seen_count"],
        "main_lan_broadcasters_visible":
            result["passive"]["main_lan_broadcasters_count"],
        "main_lan_broadcast_frames":
            result["passive"]["main_lan_broadcast_frames"],
        "mdns_service_types": result["passive"]["mdns_service_type_count"],
    }

    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            f.write(text)
        print(f"wrote {args.out}")
        print(json.dumps(result["summary"], indent=2))
    else:
        print(text)


if __name__ == "__main__":
    main()
