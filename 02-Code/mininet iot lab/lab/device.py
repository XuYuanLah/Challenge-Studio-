#!/usr/bin/env python3
"""
Device simulator for Mininet hosts.

Five generic device archetypes. Each behaviour runs on its own timer, which
is how real devices behave: their traffic is several independent periodic
loops rather than one.

  device.py camera  --resolver 192.168.0.8 --controller 192.168.0.10
  device.py sensor  --controller 192.168.0.10 --speed 60

--speed compresses time: 60 means a 24h profile plays out in 24 minutes. Use
it to develop, then run at speed 1 for the real baseline.
"""

import argparse
import json
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time

NTP_EPOCH_DELTA = 2208988800

# Five generic device archetypes. The numbers are plausible round values in
# the range real consumer devices occupy: enough variety that baselines differ
# meaningfully between devices, and simple enough to reason about.
PROFILES = {
    # Camera: the heavy one. Continuous upload to a video endpoint.
    "camera": dict(
        dns=["video.cloud.lab", "api.cloud.lab"],
        dns_interval=300.0,
        ntp=["ntp.cloud.lab"], ntp_interval=3600.0,
        cloud=[("video.cloud.lab", 443, 600.0, 240000)],
        mdns_interval=30.0, mdns_service="_rtsp._tcp.local",
        report_interval=60.0, report_port=5540,
        mb_per_hour=14.4,
    ),
    # Device hub: very chatty on mDNS, one long-lived MQTT session.
    "iot_hub": dict(
        dns=["mqtt.cloud.lab", "api.cloud.lab", "telemetry.cloud.lab"],
        dns_interval=120.0,
        ntp=["ntp.cloud.lab"], ntp_interval=3600.0,
        cloud=[("mqtt.cloud.lab", 8883, 900.0, 600)],
        http=[("diagnostics.cloud.lab", 80, 21600.0)],
        mdns_interval=1.0, mdns_service="_hap._tcp.local",
        report_interval=60.0, report_port=5540,
        mb_per_hour=1.2,
    ),
    # Plug: barely talks to the cloud; its control path is local.
    "plug": dict(
        dns=["api.cloud.lab"],
        dns_interval=7200.0,
        ntp=["ntp.cloud.lab"], ntp_interval=21600.0,
        cloud=[("api.cloud.lab", 443, 43200.0, 0)],
        mdns_interval=45.0, mdns_service="_matter._tcp.local",
        report_interval=5.0, report_port=5540,
        mb_per_hour=0.25,
    ),
    # Sensor: local only. No cloud, no DNS. Reports every 10 minutes, which is
    # long enough to fall foul of a short UDP connection-tracking timeout.
    "sensor": dict(
        dns=[], ntp=[], cloud=[],
        mdns_interval=60.0, mdns_service="_matter._tcp.local",
        report_interval=600.0, report_port=5540,
        mb_per_hour=0.06,
    ),
    # Thermostat: small periodic cloud poll, otherwise quiet.
    "thermostat": dict(
        dns=["api.cloud.lab", "updates.cloud.lab"],
        dns_interval=900.0,
        ntp=["ntp.cloud.lab"], ntp_interval=7200.0,
        cloud=[("api.cloud.lab", 443, 300.0, 400)],
        mdns_interval=120.0, mdns_service="_matter._tcp.local",
        report_interval=300.0, report_port=5540,
        mb_per_hour=0.18,
    ),
    # The controller's own local chatter. Subscribing is the controller's job.
    "controller": dict(
        dns=[], ntp=[], cloud=[],
        mdns_interval=45.0, mdns_service="_matter._tcp.local",
        report_interval=None,
        mb_per_hour=0.09,
    ),
    # A workstation: light mDNS and SMB-style presence.
    "workstation": dict(
        dns=["api.cloud.lab"], dns_interval=600.0,
        ntp=[], cloud=[],
        mdns_interval=90.0, mdns_service="_smb._tcp.local",
        report_interval=None,
        mb_per_hour=0.07,
    ),
}

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353


class Device:
    def __init__(self, args):
        self.a = args
        self.p = PROFILES[args.profile]
        self.name = args.name or args.profile
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.extra_domains = []
        self.volume_mult = 1.0
        self.logf = open(args.log, "a") if args.log else None

    # -- helpers ----------------------------------------------------------
    def scaled(self, seconds):
        return max(0.05, seconds / self.a.speed)

    def log(self, kind, **kw):
        rec = {"ts": round(time.time(), 3), "device": self.name, "kind": kind}
        rec.update(kw)
        line = json.dumps(rec, separators=(",", ":"))
        if self.logf:
            self.logf.write(line + "\n")
            self.logf.flush()
        if not self.a.quiet:
            print(line, flush=True)

    def wait(self, seconds, jitter=0.3):
        d = seconds * jitter
        return not self.stop.wait(max(0.05, random.uniform(seconds - d,
                                                           seconds + d)))

    # -- behaviours -------------------------------------------------------
    def dns_loop(self):
        while not self.stop.is_set():
            with self.lock:
                names = list(self.p["dns"]) + list(self.extra_domains)
            for n in names:
                if self.stop.is_set():
                    return
                self.resolve(n)
            if not self.wait(self.scaled(self.p["dns_interval"])):
                return

    def resolve(self, name):
        tid = random.randrange(0, 0xFFFF)
        q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        for label in name.split("."):
            q += bytes([len(label)]) + label.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(q, (self.a.resolver, 53))
            data, _ = s.recvfrom(2048)
            rcode = data[3] & 0x0F
            ancount = struct.unpack(">H", data[6:8])[0]
            if rcode == 3:
                self.log("dns", name=name, result="NXDOMAIN/blocked")
            elif ancount:
                ip = socket.inet_ntoa(data[-4:])
                self.log("dns", name=name, result=ip)
                return ip
            else:
                self.log("dns", name=name, result="no-answer")
        except Exception as e:
            self.log("dns", name=name, error=str(e)[:80])
        finally:
            s.close()
        return None

    def ntp_loop(self):
        while not self.stop.is_set():
            for server in self.p["ntp"]:
                ip = self.resolve(server) or server
                self.ntp_query(ip, server)
            if not self.wait(self.scaled(self.p["ntp_interval"])):
                return

    def ntp_query(self, ip, label):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(4)
        try:
            s.sendto(b"\x1b" + 47 * b"\0", (ip, 123))
            data, _ = s.recvfrom(256)
            t = struct.unpack(">I", data[40:44])[0] - NTP_EPOCH_DELTA
            self.log("ntp", server=label, remote_time=int(t))
        except Exception as e:
            self.log("ntp", server=label, error=str(e)[:80])
        finally:
            s.close()

    def cloud_loop(self, host, port, interval, kbpm):
        while not self.stop.is_set():
            self.cloud_session(host, port, interval, kbpm)
            if not self.wait(self.scaled(interval)):
                return

    def cloud_session(self, host, port, interval, bytes_per_min):
        ip = self.resolve(host)
        if not ip:
            self.log("cloud_blocked", host=host, port=port,
                     note="no DNS answer, cannot connect")
            return
        t0 = time.time()
        sent = 0
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=10)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # server_hostname sets the SNI, which is the metadata the
            # analysis extracts.
            sock = ctx.wrap_socket(sock, server_hostname=host)
            self.log("cloud_connect", host=host, ip=ip, port=port,
                     tls=sock.version(), cipher=sock.cipher()[0],
                     local_port=sock.getsockname()[1])
            hold = self.scaled(interval * 0.8)
            tick = self.scaled(30.0)
            deadline = time.time() + hold
            with self.lock:
                mult = self.volume_mult
            per_tick = int(bytes_per_min * (tick / 60.0) * mult)
            while time.time() < deadline and not self.stop.is_set():
                if per_tick > 0:
                    sock.sendall(b"\x00" * per_tick)
                    sent += per_tick
                    try:
                        sock.recv(4096)
                    except Exception:
                        pass
                if self.stop.wait(tick):
                    break
        except Exception as e:
            self.log("cloud_error", host=host, port=port, error=str(e)[:100])
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            self.log("cloud_close", host=host, port=port, bytes_sent=sent,
                     duration_s=round(time.time() - t0, 1))

    def http_loop(self, host, port, interval):
        """Plain HTTP POST, modelling the cleartext-diagnostics finding."""
        token = "a" * 200
        while not self.stop.is_set():
            ip = self.resolve(host)
            if ip:
                try:
                    s = socket.create_connection((ip, port), timeout=10)
                    body = json.dumps({"device": self.name, "uptime": 1})
                    req = (f"POST /v2/diagnostics/report?sso={token}"
                           f"&auth=1 HTTP/1.1\r\nHost: {host}\r\n"
                           f"Content-Length: {len(body)}\r\n\r\n{body}")
                    s.sendall(req.encode())
                    s.recv(2048)
                    s.close()
                    self.log("http_post", host=host, port=port,
                             cleartext=True, token_len=len(token))
                except Exception as e:
                    self.log("http_error", host=host, error=str(e)[:80])
            if not self.wait(self.scaled(interval)):
                return

    def mdns_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        n = 0
        try:
            while not self.stop.is_set():
                try:
                    s.sendto(self.mdns_packet(), (MDNS_GROUP, MDNS_PORT))
                    n += 1
                    if n % 200 == 0:
                        self.log("mdns", count=n,
                                 service=self.p["mdns_service"])
                except Exception as e:
                    self.log("mdns_error", error=str(e)[:80])
                if not self.wait(self.scaled(self.p["mdns_interval"]), 0.1):
                    return
        finally:
            s.close()

    def mdns_packet(self):
        def enc(fqdn):
            out = b""
            for label in fqdn.split("."):
                out += bytes([len(label)]) + label.encode()
            return out + b"\x00"
        svc = self.p["mdns_service"]
        header = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
        ptr_rd = enc(f"{self.name}.{svc}")
        ptr = enc(svc) + struct.pack(">HHIH", 12, 1, 120, len(ptr_rd)) + ptr_rd
        try:
            myip = socket.inet_aton(self.my_ip())
        except Exception:
            myip = socket.inet_aton("0.0.0.0")
        a = (enc(f"{self.name}.local")
             + struct.pack(">HHIH", 1, 0x8001, 120, 4) + myip)
        return header + ptr + a

    @staticmethod
    def my_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("203.0.113.1", 9))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

    def report_loop(self):
        port = self.p["report_port"]
        bcast = self.p.get("report_broadcast", False)
        while not self.stop.is_set():
            with self.lock:
                mult = self.volume_mult
            payload = json.dumps({"device": self.name,
                                  "ts": round(time.time(), 2),
                                  "state": random.choice(["on", "off"]),
                                  "metric": round(random.uniform(0, 100), 2)}
                                 ).encode()
            payload += b" " * max(0, int(180 * mult) - len(payload))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                if bcast:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    dst = "255.255.255.255"
                else:
                    dst = self.a.controller
                    # Source port 5540 is what makes the conntrack behaviour
                    # reproducible; harmless if it is unavailable.
                    try:
                        s.bind(("", port))
                    except OSError:
                        pass
                s.sendto(payload, (dst, port))
                self.log("report", dst=dst, dport=port, bytes=len(payload))
            except Exception as e:
                self.log("report_error", error=str(e)[:80])
            finally:
                s.close()
            if not self.wait(self.scaled(self.p["report_interval"]), 0.15):
                return

    # -- lifecycle --------------------------------------------------------
    def start(self):
        p = self.p
        jobs = []
        if p.get("dns"):
            jobs.append(("dns", self.dns_loop))
        if p.get("ntp"):
            jobs.append(("ntp", self.ntp_loop))
        for host, port, interval, kbpm in p.get("cloud", []):
            jobs.append((f"cloud:{host}:{port}",
                         lambda h=host, pt=port, iv=interval, kb=kbpm:
                         self.cloud_loop(h, pt, iv, kb)))
        for host, port, interval in p.get("http", []):
            jobs.append((f"http:{host}",
                         lambda h=host, pt=port, iv=interval:
                         self.http_loop(h, pt, iv)))
        if p.get("mdns_interval"):
            jobs.append(("mdns", self.mdns_loop))
        if p.get("report_interval"):
            jobs.append(("report", self.report_loop))
        self.log("device_start", profile=self.a.profile,
                 mb_per_hour=p["mb_per_hour"], speed=self.a.speed,
                 jobs=[n for n, _ in jobs])
        for n, fn in jobs:
            threading.Thread(target=fn, daemon=True,
                             name=f"{self.name}/{n}").start()
        return [n for n, _ in jobs]

    def shutdown(self):
        self.stop.set()
        self.log("device_stop")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("profile", choices=sorted(PROFILES))
    ap.add_argument("--name", default="")
    ap.add_argument("--resolver", default="192.168.0.8")
    ap.add_argument("--controller", default="192.168.0.10")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="time compression; 60 plays 24h in 24 minutes")
    ap.add_argument("--duration", type=float, default=0)
    ap.add_argument("--log", default="")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--anomaly", default="",
                    help="new_domain | volume_spike | beacon_slow")
    ap.add_argument("--anomaly-at", type=float, default=0)
    ap.add_argument("--anomaly-duration", type=float, default=300)
    args = ap.parse_args()

    dev = Device(args)
    dev.start()

    t0 = time.time()
    fired = False
    try:
        while True:
            el = time.time() - t0
            if args.anomaly and not fired and el >= args.anomaly_at:
                fired = True
                dev.log("anomaly_start", anomaly=args.anomaly,
                        duration_s=args.anomaly_duration)
                if args.anomaly == "new_domain":
                    with dev.lock:
                        dev.extra_domains.append("unexpected-server.evil.lab")
                elif args.anomaly == "volume_spike":
                    with dev.lock:
                        dev.volume_mult = 20.0
                elif args.anomaly == "beacon_slow":
                    dev.p["report_interval"] = 900.0

                def end():
                    time.sleep(args.anomaly_duration)
                    if args.anomaly == "new_domain":
                        with dev.lock:
                            dev.extra_domains.clear()
                    elif args.anomaly == "volume_spike":
                        with dev.lock:
                            dev.volume_mult = 1.0
                    dev.log("anomaly_end", anomaly=args.anomaly)
                threading.Thread(target=end, daemon=True).start()
            if args.duration and el >= args.duration:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        dev.shutdown()


if __name__ == "__main__":
    main()
