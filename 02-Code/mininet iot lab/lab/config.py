"""
Lab inventory and addressing.

A generic smart-home network: five IoT devices, a small main LAN, two VLANs.
Change the environment here; the topology code reads this and nothing else.

The device profiles are deliberately archetypes rather than specific products
(a camera, a hub, a plug, a sensor, a thermostat). Their traffic parameters are
plausible round numbers in the range real devices occupy, which is what makes
the baselines readable and the detection thresholds defensible.
"""

# --- VLANs -----------------------------------------------------------------
VLAN_MAIN = 1
VLAN_IOT = 107

# --- subnets ---------------------------------------------------------------
NET_MAIN = "192.168.0.0/24"
NET_IOT = "192.168.107.0/27"
NET_WAN = "203.0.113.0/24"

GW_MAIN = "192.168.0.1"
GW_IOT = "192.168.107.1"

PREFIX_MAIN = 24
PREFIX_IOT = 27

ROUTER_WAN_IP = "203.0.113.2"
CLOUD_IP = "203.0.113.10"
CLOUD_PREFIX = 24

RESOLVER_IP = "192.168.0.8"      # the DNS server every device must use
CONTROLLER_IP = "192.168.0.10"   # the hub/controller the devices report to

# Services the router itself runs. These exist so the prober can show that a
# FORWARD policy does not protect the router: traffic addressed to the router
# goes through INPUT, which segmentation alone never touches.
ROUTER_SERVICE_PORTS = [22, 53, 81, 8200]

# Ports the prober tries on every host it finds.
PROBE_PORTS = [22, 53, 80, 81, 443, 445, 1883, 5540, 8080, 8200, 8443, 8883]


class Node:
    """One lab host."""

    def __init__(self, name, role, ip_flat, ip_seg=None, profile=None,
                 services=(), desc=""):
        self.name = name
        self.role = role              # main | iot
        self.ip_flat = ip_flat
        self.ip_seg = ip_seg or ip_flat
        self.profile = profile
        self.services = list(services)
        self.desc = desc

    def ip(self, mode):
        return self.ip_flat if mode == "flat" else self.ip_seg

    def prefix(self, mode):
        if mode == "flat":
            return PREFIX_MAIN
        return PREFIX_MAIN if self.role == "main" else PREFIX_IOT

    def gateway(self, mode):
        if mode == "flat":
            return GW_MAIN
        return GW_MAIN if self.role == "main" else GW_IOT

    def vlan_for(self, mode):
        """In flat mode everything shares VLAN 1. Moving the IoT devices to
        VLAN 107 is the single change the experiment makes."""
        if mode == "flat" or self.role == "main":
            return VLAN_MAIN
        return VLAN_IOT


# --- the inventory ---------------------------------------------------------
# Short names: Mininet builds interface names from them.

NODES = [
    # --- main LAN ---
    Node("dns", "main", "192.168.0.8", services=[53],
         desc="DNS server for the whole network"),
    Node("hub", "main", "192.168.0.10", profile="controller",
         services=[5540, 80],
         desc="smart-home controller; the devices report to it"),
    Node("pc", "main", "192.168.0.20", profile="workstation",
         services=[22, 445],
         desc="a workstation with file sharing"),
    Node("nas", "main", "192.168.0.30", services=[22, 445, 8200],
         desc="network storage, the host worth protecting"),

    # --- the five IoT devices: flat IP -> segmented IP ---
    Node("iotcam", "iot", "192.168.0.101", "192.168.107.10",
         profile="camera", services=[80, 554],
         desc="camera: continuous upload, highest volume"),
    Node("iothub", "iot", "192.168.0.102", "192.168.107.11",
         profile="iot_hub", services=[80],
         desc="device hub: chatty on mDNS, long-lived cloud session"),
    Node("iotplug", "iot", "192.168.0.103", "192.168.107.12",
         profile="plug",
         desc="smart plug: almost no cloud traffic, heavy local control"),
    Node("iotsens", "iot", "192.168.0.104", "192.168.107.13",
         profile="sensor",
         desc="sensor: local only, reports every 10 minutes"),
    Node("iottherm", "iot", "192.168.0.105", "192.168.107.14",
         profile="thermostat",
         desc="thermostat: small periodic cloud poll"),
]

BY_NAME = {n.name: n for n in NODES}
IOT_NODES = [n for n in NODES if n.role == "iot"]
MAIN_NODES = [n for n in NODES if n.role == "main"]


def ips_for_role(role, mode):
    return {n.ip(mode) for n in NODES if n.role == role}


# --- DNS zone --------------------------------------------------------------
# Everything resolves to the single cloud host. ".lab" keeps the names clearly
# synthetic and unresolvable outside the lab.
DNS_ZONE = {
    "api.cloud.lab": CLOUD_IP,
    "telemetry.cloud.lab": CLOUD_IP,
    "updates.cloud.lab": CLOUD_IP,
    "mqtt.cloud.lab": CLOUD_IP,
    "video.cloud.lab": CLOUD_IP,
    "ntp.cloud.lab": CLOUD_IP,
    "diagnostics.cloud.lab": CLOUD_IP,
    "unexpected-server.evil.lab": CLOUD_IP,
}

# Names the resolver refuses, modelling a blocklist. A device that keeps
# retrying a blocked name is a detectable pattern in its own right.
DNS_BLOCKED = {"telemetry.cloud.lab"}

# --- cloud endpoints -------------------------------------------------------
CLOUD_TLS_PORTS = [443, 8883]
CLOUD_HTTP_PORT = 80
CLOUD_NTP_PORT = 123
