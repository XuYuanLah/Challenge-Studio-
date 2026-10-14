# Mininet IoT lab: five devices, VLAN segmentation, before/after exposure

Five generic IoT devices, a small main LAN, two
VLANs, and a measured comparison of what an IoT device can reach and see
before and after segmentation.

Standard library Python plus Mininet, Open vSwitch and `tcpdump`. No
controller, no SDN programming, nothing from pip.

## What it does

1. Builds the network in Mininet, in one of three states.
2. Runs five simulated IoT devices with distinct traffic profiles.
3. Captures traffic at the devices.
4. Measures what an IoT device can reach and what it can see.
5. Prints a before/after comparison and extracts per-device baselines.

### The three states

| state | what changes |
|---|---|
| `flat` | Everything shares VLAN 1 and `192.168.0.0/24`. No policy. The IoT devices sit in the main LAN's broadcast domain. |
| `segmented` | IoT devices move to VLAN 107 and `192.168.107.0/27`. One-way FORWARD policy with `IOT_TO_LAN_DROP` logging. |
| `hardened` | As `segmented`, plus INPUT rules protecting the router itself, DNS forced to the resolver, DNS-over-TLS dropped. |

Only the IoT VLAN, the IoT subnet and the firewall policy differ between
states, so any change in the results is attributable to the segmentation.

## Topology

```
  cloud 203.0.113.10 ── s0 ── r1 ── s1 ─┬─ VLAN 1    main LAN 192.168.0.0/24
   (TLS, HTTP, NTP        (router)       │            dns .8    hub .10
    endpoints)                           │            pc  .20   nas .30
                                         │
                                         └─ VLAN 107  IoT 192.168.107.0/27
                                                      iotcam, iothub, iotplug,
                                                      iotsens, iottherm
```

`r1` is an ordinary Linux host with `ip_forward=1` and `iptables`, so the
policy is real rather than approximated.

### The five devices

| device | profile | behaviour |
|---|---|---|
| `iotcam` | camera | continuous upload, highest volume (~14 MB/h) |
| `iothub` | hub | very chatty mDNS, long-lived MQTT/TLS on 8883, cleartext HTTP diagnostics |
| `iotplug` | plug | almost no cloud traffic; control path is local |
| `iotsens` | sensor | local only, no cloud, no DNS, reports every 10 min |
| `iottherm` | thermostat | small periodic cloud poll |

The variety is the point: a detector that works on all five has to cope with a
heavy uploader and a near-silent local-only sensor in the same ruleset.
`iotsens` reporting every 600 s is also what exposes a short UDP
connection-tracking timeout.

## Requirements

- Linux with Mininet and Open vSwitch:
  `sudo apt install mininet openvswitch-switch tcpdump ethtool`
- Root, for namespaces and veth pairs.

Check with `sudo mn --test pingall`.

## Running it

All three states with a comparison at the end:

```bash
sudo python3 run_experiment.py --speed 60 --settle 120 --listen 60 --capture
```

One state, with an interactive prompt:

```bash
sudo python3 iot_lab.py --mode segmented --cli
```

```
mininet> iotcam ping -c2 192.168.0.30     # allowed: ICMP is permitted
mininet> iotcam python3 -c "import socket;print(socket.socket().connect_ex(('192.168.0.30',445)))"
mininet> r1 iptables -L FORWARD -n -v     # watch the drop counters climb
mininet> r1 dmesg | tail                  # IOT_TO_LAN_DROP log lines
```

Baselines from a capture:

```bash
python3 analyse_pcap.py results/flat/iotcam-flat.pcap --speed 60
python3 analyse_pcap.py results/*/iotcam-*.pcap --compare
```

### Useful flags

- `--speed N` compresses device time: `60` plays a 24-hour profile in 24
  minutes. Develop fast, then take the real baseline at `--speed 1`. Pass the
  same value to `analyse_pcap.py --speed` and the time-valued figures
  (intervals, flow durations) are rescaled back to real-world equivalents.
  Volume per hour needs no rescaling: compressing time shrinks both the bytes
  and the elapsed time, so the rate is already the real one.
- `--datapath user` for machines without the OVS kernel module.
- `--trunk` gives the router one real 802.1Q trunk with VLAN subinterfaces
  instead of an access port per VLAN. Needs the `8021q` module.
- `--capture` runs `tcpdump` on the `iotcam` and `iotsens` links — the busiest
  device and the quietest.
- `--probe-from` chooses which device the prober runs on.

## Results from a real run

Three states, `--speed 120 --settle 15 --listen 15`, probed from `iotcam`:

```
                                        flat     segmented      hardened
main-LAN TCP services reachable            8             1             1
open TCP ports found in total             17            14             6
devices visible passively (src MACs)       9             6             6
main-LAN hosts visible passively           3             2             2
main-LAN hosts broadcasting to it          2             0             0
main-LAN broadcast frames received        61             0             0
mDNS service types exposed                 4             3             3
router TCP ports reachable     22,53,81,8200 22,53,81,8200          none
```

Three things worth drawing out:

- **Main-LAN broadcast reaching the device goes 61 → 0.** In the flat state
  the IoT devices share a broadcast domain with the main LAN, so they receive
  its mDNS and broadcast traffic without asking for any of it. This is the
  passive half of exposure, and it is the half a device with no credentials
  still benefits from.
- **Router ports survive segmentation untouched and only close when
  hardened.** `22,53,81,8200` are still reachable after the move to VLAN 107,
  because a FORWARD policy says nothing about traffic addressed to the router
  itself — that goes through INPUT. This is the single most transferable
  finding in the lab, and it only shows up when you test from inside the IoT
  segment rather than from the main LAN.
- **The one remaining main-LAN service is DNS on port 53**, which the policy
  allows deliberately. A metric that fell to zero would mean DNS was broken,
  not that segmentation was working better.

Magnitudes scale with `--speed`, `--settle` and `--listen`; the directions are
stable.

## How exposure is measured

`recon.py` runs **on** a device and separates two questions:

- **Active**: what can it reach? ICMP sweep plus TCP connect across the lab's
  subnets and both router addresses.
- **Passive**: what can it see unasked? It listens on its own interface and
  counts source MACs, main-LAN sources, broadcast and multicast, VLAN tags and
  mDNS service types.

Passive listening runs first. The active scan provokes
replies from the whole lab, and if it ran first those replies would be counted
as things the device could see unprompted.

Two artefacts the prober handles rather than reporting as findings:

- **DNS redirection makes port 53 look open everywhere.** With the hardened
  router DNAT-ing all port-53 traffic to the resolver, a TCP connect to any
  address on port 53 succeeds. The prober first probes an address that is
  certainly unused; if that answers on 53, it knows a redirect is in force and
  discounts port 53 elsewhere. Without this the hardened state looks *worse*
  than the segmented one.
- **The kernel strips VLAN tags before AF_PACKET.** A naive raw socket sees no
  tag even when `tcpdump` on the same interface shows one. The prober enables
  `PACKET_AUXDATA` and reads the tag from auxiliary data.

## Baselines the analyser produces

`analyse_pcap.py` reads a pcap with no dependencies and reports, per device,
the full baseline the project defines:

- destination addresses, and destination domains via DNS and TLS SNI
- protocols and ports
- connection frequency: new connections, and median, minimum and maximum
  interval between them per destination
- traffic volume, split into total and external, normalised to MB/hour
- flow duration, including the longest external flow
- DNS metadata: query names, distinct-name count, blocked-name answers
- TLS metadata: SNI and negotiated version
- cleartext HTTP destinations

The TLS version comes from the `supported_versions` extension, not the legacy
version field. A TLS 1.2 or 1.3 client still writes `0x0301` into
`legacy_version`, so reading that field alone labels every modern client as
TLS 1.0 — a false positive on any "TLS below 1.2" rule.

## Reproducing a connection-tracking drop

The hub sends subscribe packets to each device; each device reports back from
UDP 5540. The reply only passes while the router's conntrack entry from the
hub's outbound packet is alive.

```bash
sudo python3 iot_lab.py --mode segmented --cli
mininet> r1 sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180
mininet> r1 iptables -L FORWARD -n -v | grep -i drop      # watch it climb
mininet> r1 sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=1800
```

`iotsens` reports every 600 s, so against a 180 s timeout it drops and against
1800 s it does not. Vary its interval with `--report-interval` to bracket the
threshold instead of just showing the symptom. This is a policy false
positive: legitimate traffic dropped by a correct-looking rule, which is worth
a section of its own in any segmentation write-up.

## Scope and limits

- **Active scanning happens.** `recon.py` sweeps the lab's own subnets only,
  and the lab is entirely synthetic, so nothing outside it is touched.
- **NIC offload is disabled on every interface.** Two reasons. With the OVS
  userspace datapath, TX checksum offload silently breaks TCP while leaving
  ICMP working. And TSO/GSO hand `tcpdump` oversized pseudo-frames, which
  distorts the very packet counts and frame sizes being measured. The general
  lesson holds on real hardware too: a capture is only complete if offload is
  off.
- **The devices are archetypes, not products.** They reproduce destinations,
  intervals, volumes and protocol mix, not vendor firmware. They will not
  reproduce a vendor bug or a real TLS stack's fingerprint.
- **IPv4 only.** No IPv6, so nothing here covers ULAs, NAT6, RDNSS or Thread.
- **Timing is compressed** unless you run at `--speed 1`. Always state the
  speed next to any interval you quote.

## Files

- `iot_lab.py` — topology, VLAN tagging, addressing, firewall policy. Start here.
- `lab/config.py` — inventory, addressing, DNS zone and blocklist. Change the
  environment here, not in the topology code.
- `lab/device.py` — the five device profiles and the simulator.
- `lab/services.py` — resolver with a blocklist, cloud TLS/HTTP/NTP endpoints,
  the hub controller, and plain TCP listeners.
- `recon.py` — exposure prober, active and passive.
- `run_experiment.py` — runs each state and prints the comparison.
- `analyse_pcap.py` — per-device baselines from a pcap.
- `selftest.py` — quick connectivity assertions per mode.

### Adding or changing devices

Everything lives in `lab/config.py` and `lab/device.py`. Add a `Node(...)` to
`NODES` with `role="iot"`, a flat IP and a segmented IP, and point `profile` at
an entry in `PROFILES`. New traffic shapes are a dict in `PROFILES`: DNS names
and interval, NTP, cloud endpoints as `(host, port, reconnect_interval,
bytes_per_minute)`, mDNS interval and service type, and report interval. The
topology, firewall, prober and analyser all pick it up with no other changes.

## Troubleshooting

- **TCP fails but ping works** — offload is on somewhere. The lab disables it;
  if you add hosts yourself, run `ethtool -K <iface> tx off rx off`.
- **`ovs-vsctl` cannot connect** — Open vSwitch is not running. Start it with
  `systemctl start openvswitch-switch`, or launch `ovsdb-server` and
  `ovs-vswitchd` by hand.
- **The switch never forwards** — switches are created with
  `failMode=standalone` so they learn like ordinary switches with no
  controller. If you change that, you need one.
- **Stale state between runs** — `sudo mn -c`.
- **`--trunk` fails** — the `8021q` module is missing. Use the default mode.
