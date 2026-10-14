#!/usr/bin/env python3
"""
Mininet IoT lab: a generic five-device smart-home network in three states.

    sudo python3 iot_lab.py --mode flat
    sudo python3 iot_lab.py --mode segmented
    sudo python3 iot_lab.py --mode hardened --cli

Topology:

    cloud(203.0.113.10) --- s0 --- r1 --- s1 ---+--- VLAN 1   main LAN
                                                 |
                                                 +--- VLAN 107 the 5 IoT devices

Only three things differ between the modes, which keeps the experiment clean:

  flat       Everything shares VLAN 1 and 192.168.0.0/24. No firewall policy.
             The IoT devices sit in the same broadcast domain as the main LAN,
             so they see all of its broadcast and mDNS traffic.
  segmented  The IoT devices move to VLAN 107 and 192.168.107.0/27, with a
             one-way FORWARD policy and IOT_TO_LAN_DROP logging.
  hardened   As segmented, plus INPUT rules protecting the router itself, DNS
             forced to the resolver, and DNS-over-TLS dropped. A FORWARD
             policy never covers traffic addressed to the router, so the
             router stays exposed until this step.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mininet.net import Mininet
from mininet.node import OVSSwitch, Node as MNNode
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from lab import config as C

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


class LinuxRouter(MNNode):
    """A host that forwards."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


def build(mode, datapath="kernel", trunk_router=False):
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True,
                  waitConnected=False)

    s_lan = net.addSwitch("s1", failMode="standalone", datapath=datapath)
    s_wan = net.addSwitch("s0", failMode="standalone", datapath=datapath)

    r1 = net.addHost("r1", cls=LinuxRouter, ip=None)
    cloud = net.addHost("cloud", ip=f"{C.CLOUD_IP}/{C.CLOUD_PREFIX}")

    # WAN side
    net.addLink(r1, s_wan)
    net.addLink(cloud, s_wan)

    # Router legs into the LAN switch.
    # Default: one access port per VLAN, which needs no 802.1Q on the host and
    # therefore runs anywhere. --trunk gives a single real trunk instead.
    router_links = {}
    if trunk_router:
        router_links["trunk"] = net.addLink(r1, s_lan)
    else:
        for vlan in (C.VLAN_MAIN, C.VLAN_IOT):
            router_links[vlan] = net.addLink(r1, s_lan)

    # Hosts
    hosts = {}
    host_links = {}
    for n in C.NODES:
        h = net.addHost(n.name, ip=None)
        hosts[n.name] = h
        host_links[n.name] = net.addLink(h, s_lan)

    net.start()

    # ---- addressing ----
    wan_if = r1.intf("r1-eth0")
    r1.cmd(f"ip addr flush dev {wan_if}")
    r1.cmd(f"ip addr add {C.ROUTER_WAN_IP}/{C.CLOUD_PREFIX} dev {wan_if}")
    r1.cmd(f"ip link set {wan_if} up")

    cloud.cmd(f"ip route add default via {C.ROUTER_WAN_IP}")

    if trunk_router:
        base = router_links["trunk"].intf1.name
        r1.cmd(f"ip link set {base} up")
        for vlan, gw, plen in ((C.VLAN_MAIN, C.GW_MAIN, C.PREFIX_MAIN),
                               (C.VLAN_IOT, C.GW_IOT, C.PREFIX_IOT)):
            sub = f"{base}.{vlan}"
            r1.cmd(f"ip link add link {base} name {sub} type vlan id {vlan}")
            r1.cmd(f"ip addr add {gw}/{plen} dev {sub}")
            r1.cmd(f"ip link set {sub} up")
        r1.gw_ifaces = {C.VLAN_MAIN: f"{base}.{C.VLAN_MAIN}",
                        C.VLAN_IOT: f"{base}.{C.VLAN_IOT}"}
    else:
        r1.gw_ifaces = {}
        for vlan, gw, plen in ((C.VLAN_MAIN, C.GW_MAIN, C.PREFIX_MAIN),
                               (C.VLAN_IOT, C.GW_IOT, C.PREFIX_IOT)):
            intf = router_links[vlan].intf1.name
            r1.cmd(f"ip addr flush dev {intf}")
            r1.cmd(f"ip addr add {gw}/{plen} dev {intf}")
            r1.cmd(f"ip link set {intf} up")
            r1.gw_ifaces[vlan] = intf

    # In flat mode the IoT devices live in the main subnet, so the router's
    # 107 leg has nothing behind it. Take the address off so it cannot
    # accidentally provide a path the flat state should not have.
    if mode == "flat":
        r1.cmd(f"ip addr del {C.GW_IOT}/{C.PREFIX_IOT} "
               f"dev {r1.gw_ifaces[C.VLAN_IOT]} 2>/dev/null")

    for n in C.NODES:
        h = hosts[n.name]
        intf = host_links[n.name].intf1.name
        ip, plen, gw = n.ip(mode), n.prefix(mode), n.gateway(mode)
        h.cmd(f"ip addr flush dev {intf}")
        h.cmd(f"ip addr add {ip}/{plen} dev {intf}")
        h.cmd(f"ip link set {intf} up")
        h.cmd(f"ip route add default via {gw}")
        h.setIP(ip, plen, intf=intf)

    # ---- disable NIC offload on every interface ----
    # Two reasons. With the OVS userspace datapath, TX checksum offload
    # produces segments the receiver discards, so TCP fails while ICMP works -
    # a confusing failure. And offload lets the kernel hand tcpdump oversized
    # pseudo-frames (TSO/GSO), which distorts packet counts and frame sizes in
    # exactly the baseline measurements this lab exists to take. This is the
    # software counterpart of disabling flow-cache offload on the real router.
    for node in [r1, cloud] + list(hosts.values()):
        for intf in node.intfList():
            if intf.name != "lo":
                node.cmd(f"ethtool -K {intf.name} tx off rx off sg off "
                         f"tso off gso off gro off 2>/dev/null")

    # ---- VLAN tagging on the switch ----
    apply_vlans(net, mode, router_links, host_links, trunk_router)

    # ---- firewall ----
    apply_firewall(r1, mode)

    return net, hosts, r1, cloud


def ovs(cmd):
    return os.popen(f"ovs-vsctl {cmd} 2>&1").read().strip()


def apply_vlans(net, mode, router_links, host_links, trunk_router):
    """Tag the switch ports. This is where the segmentation actually lives."""
    info("*** configuring VLANs on s1\n")

    # Router port(s)
    if trunk_router:
        port = router_links["trunk"].intf2.name
        ovs(f"set port {port} vlan_mode=trunk "
            f"trunks={C.VLAN_MAIN},{C.VLAN_IOT}")
    else:
        for vlan, link in router_links.items():
            ovs(f"set port {link.intf2.name} tag={vlan}")

    # Host ports: every host is a plain access port in its VLAN.
    for n in C.NODES:
        port = host_links[n.name].intf2.name
        ovs(f"clear port {port} trunks")
        ovs(f"set port {port} vlan_mode=access tag={n.vlan_for(mode)}")


def apply_firewall(r1, mode):
    """The one-way policy, and in hardened mode the router's own protection."""
    info(f"*** applying firewall policy for mode={mode}\n")
    r1.cmd("iptables -F; iptables -t nat -F; iptables -P FORWARD ACCEPT; "
           "iptables -P INPUT ACCEPT")
    wan = "r1-eth0"
    r1.cmd(f"iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE")

    if mode == "flat":
        # Nothing else. Everything can reach everything, which is the point.
        return

    iot_if = r1.gw_ifaces[C.VLAN_IOT]
    main_if = r1.gw_ifaces[C.VLAN_MAIN]

    # Order matters; each rule is appended in the order it should be read.
    rules = [
        # replies to traffic the main LAN started
        f"-i {iot_if} -o {main_if} -m conntrack "
        f"--ctstate ESTABLISHED,RELATED -j ACCEPT",
        # DNS to the resolver only
        f"-i {iot_if} -o {main_if} -p udp -d {C.RESOLVER_IP} --dport 53 -j ACCEPT",
        f"-i {iot_if} -o {main_if} -p tcp -d {C.RESOLVER_IP} --dport 53 -j ACCEPT",
        # ping, for troubleshooting
        f"-i {iot_if} -o {main_if} -p icmp --icmp-type echo-request -j ACCEPT",
        # controllers initiate: main LAN -> IoT is allowed
        f"-i {main_if} -o {iot_if} -j ACCEPT",
        # everything else from IoT to the main LAN is logged and dropped
        f"-i {iot_if} -o {main_if} -m limit --limit 10/min "
        f"-j LOG --log-prefix \"IOT_TO_LAN_DROP \"",
        f"-i {iot_if} -o {main_if} -j DROP",
    ]
    for rule in rules:
        r1.cmd(f"iptables -A FORWARD {rule}")

    if mode == "hardened":
        # Traffic addressed to the router itself goes through INPUT, which the
        # FORWARD policy above never touches. This is the gap that only
        # appeared when testing from inside the IoT VLAN.
        r1.cmd("iptables -A INPUT -i lo -j ACCEPT")
        r1.cmd("iptables -A INPUT -m conntrack "
               "--ctstate ESTABLISHED,RELATED -j ACCEPT")
        for proto, port in (("udp", 67), ("udp", 123), ("udp", 5353)):
            r1.cmd(f"iptables -A INPUT -i {iot_if} -p {proto} "
                   f"--dport {port} -j ACCEPT")
        r1.cmd(f"iptables -A INPUT -i {iot_if} -p icmp "
               f"--icmp-type echo-request -j ACCEPT")
        # Force DNS to the resolver rather than letting devices pick.
        r1.cmd(f"iptables -t nat -A PREROUTING -i {iot_if} -p udp --dport 53 "
               f"-j DNAT --to-destination {C.RESOLVER_IP}:53")
        r1.cmd(f"iptables -t nat -A PREROUTING -i {iot_if} -p tcp --dport 53 "
               f"-j DNAT --to-destination {C.RESOLVER_IP}:53")
        # DNS-over-TLS gets dropped and logged.
        r1.cmd(f"iptables -A FORWARD -i {iot_if} -p tcp --dport 853 "
               f"-m limit --limit 5/min -j LOG --log-prefix \"DOT_DROP \"")
        r1.cmd(f"iptables -A FORWARD -i {iot_if} -p tcp --dport 853 -j DROP")
        r1.cmd(f"iptables -A INPUT -i {iot_if} -m limit --limit 10/min "
               f"-j LOG --log-prefix \"IOT_TO_ROUTER_DROP \"")
        r1.cmd(f"iptables -A INPUT -i {iot_if} -j DROP")


def start_services(hosts, r1, cloud, mode, speed, logdir, quiet=True):
    """Bring up the resolver, cloud, controller, host services and devices."""
    info("*** starting lab services\n")
    os.makedirs(logdir, exist_ok=True)
    q = "--quiet" if quiet else ""
    svc = os.path.join(HERE, "lab", "services.py")
    dev = os.path.join(HERE, "lab", "device.py")

    # Find the resolver and controller by address, so renaming a host in
    # config.py does not break this.
    resolver_name = next(n.name for n in C.NODES
                         if n.ip(mode) == C.RESOLVER_IP)
    controller_name = next(n.name for n in C.NODES
                           if n.ip(mode) == C.CONTROLLER_IP)

    cloud.cmd(f"{PY} {svc} cloud {q} > {logdir}/cloud.log 2>&1 &")
    hosts[resolver_name].cmd(
        f"{PY} {svc} resolver --query-log {logdir}/dns-queries.jsonl {q} "
        f"> {logdir}/resolver.log 2>&1 &")

    # The router's own services, so a prober can discover them. In hardened
    # mode they still run - they are simply no longer reachable, which is the
    # distinction the experiment is making.
    ports = ",".join(str(p) for p in C.ROUTER_SERVICE_PORTS)
    r1.cmd(f"{PY} {svc} listen {ports} > {logdir}/r1-services.log 2>&1 &")

    iot_ips = ",".join(n.ip(mode) for n in C.IOT_NODES)
    hosts[controller_name].cmd(
        f"{PY} {svc} controller --subscribe {iot_ips} "
        f"--subscribe-interval {max(1.0, 600.0/speed):.1f} "
        f"--summary-interval {max(10.0, 300.0/speed):.0f} {q} "
        f"> {logdir}/controller.log 2>&1 &")

    for n in C.NODES:
        if n.services:
            p = ",".join(str(x) for x in n.services)
            hosts[n.name].cmd(
                f"{PY} {svc} listen {p} > {logdir}/{n.name}-svc.log 2>&1 &")

    time.sleep(2)

    for n in C.NODES:
        if not n.profile:
            continue
        hosts[n.name].cmd(
            f"{PY} {dev} {n.profile} --name {n.name} "
            f"--resolver {C.RESOLVER_IP} --controller {C.CONTROLLER_IP} "
            f"--speed {speed} --log {logdir}/dev-{n.name}.jsonl --quiet "
            f"> {logdir}/dev-{n.name}.log 2>&1 &")
    info("*** devices running\n")


def start_capture(hosts, r1, mode, logdir, host_links=None):
    """Capture on two IoT device links: the busiest device and a quiet one.

    Capturing at the device rather than at the router is deliberate: it shows
    what each device both sends and is exposed to.
    """
    os.makedirs(logdir, exist_ok=True)
    caps = []
    for name in ("iotcam", "iotsens"):
        h = hosts[name]
        intf = h.defaultIntf().name
        pcap = f"{logdir}/{name}-{mode}.pcap"
        h.cmd(f"tcpdump -i {intf} -s 0 -w {pcap} -U "
              f"> {logdir}/{name}-tcpdump.log 2>&1 &")
        caps.append(pcap)
    info(f"*** capturing to {', '.join(caps)}\n")
    return caps


def stop_all(net, hosts, r1, cloud):
    for h in list(hosts.values()) + [r1, cloud]:
        h.cmd("pkill -f lab/device.py; pkill -f lab/services.py; "
              "pkill tcpdump")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["flat", "segmented", "hardened"],
                    default="flat")
    ap.add_argument("--datapath", choices=["kernel", "user"], default="kernel",
                    help="use 'user' where the OVS kernel module is absent")
    ap.add_argument("--trunk", action="store_true",
                    help="give the router one real 802.1Q trunk instead of "
                         "an access port per VLAN (needs the 8021q module)")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="time compression for device profiles")
    ap.add_argument("--duration", type=float, default=0,
                    help="seconds to run before shutting down; 0 = CLI")
    ap.add_argument("--logdir", default="results")
    ap.add_argument("--capture", action="store_true")
    ap.add_argument("--no-services", action="store_true")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    setLogLevel("info" if args.verbose else "warning")
    logdir = os.path.abspath(os.path.join(args.logdir, args.mode))

    print(f"*** building lab: mode={args.mode} datapath={args.datapath} "
          f"trunk={args.trunk}")
    net, hosts, r1, cloud = build(args.mode, args.datapath, args.trunk)

    print(f"*** addressing:")
    for n in C.NODES:
        print(f"      {n.name:9s} {n.role:5s} vlan={n.vlan_for(args.mode):3d} "
              f"{n.ip(args.mode)}/{n.prefix(args.mode):<3d} {n.desc}")

    if args.capture:
        start_capture(hosts, r1, args.mode, logdir)
    if not args.no_services:
        start_services(hosts, r1, cloud, args.mode, args.speed, logdir,
                       quiet=not args.verbose)

    try:
        if args.duration:
            print(f"*** running for {args.duration:.0f}s "
                  f"(logs in {logdir})")
            time.sleep(args.duration)
        elif args.cli or not args.duration:
            print(f"*** lab is up. logs in {logdir}")
            print("*** try:  hue ping -c2 192.168.0.13   |   "
                  "r1 iptables -L FORWARD -n -v")
            CLI(net)
    finally:
        print("*** stopping")
        stop_all(net, hosts, r1, cloud)
        net.stop()


if __name__ == "__main__":
    main()
