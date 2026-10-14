#!/usr/bin/env python3
"""
Lab services. Run on a Mininet host; each one is a role.

  services.py resolver            # Pi-hole stand-in: DNS with a blocklist
  services.py cloud               # internet endpoints: TLS (with SNI), HTTP, NTP
  services.py controller          # hub: receives Matter-style reports
  services.py listen 22,445,8200  # open some TCP ports so a prober finds them

All of it is standard library plus openssl for the one-off certificate.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import config  # noqa: E402

NTP_EPOCH_DELTA = 2208988800


def log(role, msg):
    print(f"{time.strftime('%H:%M:%S')} [{role}] {msg}", flush=True)


# --------------------------------------------------------------------------
# Resolver (Pi-hole stand-in)
# --------------------------------------------------------------------------

def parse_qname(data, offset=12):
    labels = []
    i = offset
    while i < len(data) and data[i] != 0:
        n = data[i]
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(labels), i + 1


def run_resolver(args):
    """Answer A queries from the zone; refuse blocked names.

    Logging every query to a file gives the equivalent of the Pi-hole query
    log, which is what the blocked-domain retry-storm rule reads.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    log("resolver", f"listening on UDP 53; {len(config.DNS_ZONE)} names, "
                    f"{len(config.DNS_BLOCKED)} blocked")
    qlog = open(args.query_log, "a") if args.query_log else None

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            continue
        if len(data) < 13:
            continue
        tid = data[:2]
        qname, end = parse_qname(data)
        qtype = struct.unpack(">H", data[end:end + 2])[0] if len(data) >= end + 2 else 1
        question = data[12:end + 4]
        name = qname.lower()
        blocked = name in config.DNS_BLOCKED
        ip = config.DNS_ZONE.get(name)

        if blocked or ip is None or qtype != 1:
            # NXDOMAIN. A blocked name and an unknown name look the same to
            # the client, which is how a blocklist behaves.
            flags = 0x8183 if (blocked or ip is None) else 0x8180
            resp = tid + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + question
        else:
            resp = tid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question
            resp += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
            resp += socket.inet_aton(ip)

        sock.sendto(resp, addr)
        verdict = "BLOCKED" if blocked else ("NXDOMAIN" if ip is None else ip)
        if qlog:
            qlog.write(json.dumps({"ts": round(time.time(), 3),
                                   "client": addr[0], "name": name,
                                   "qtype": qtype, "result": verdict}) + "\n")
            qlog.flush()
        if not args.quiet:
            log("resolver", f"{addr[0]} ? {name} -> {verdict}")


# --------------------------------------------------------------------------
# Cloud endpoints
# --------------------------------------------------------------------------

def ensure_cert(certdir="/tmp/lab-certs"):
    """Self-signed cert so devices complete a real TLS handshake.

    A completed handshake matters: it gives realistic session duration and
    byte counts, and the ClientHello carries the SNI the analysis reads.
    """
    os.makedirs(certdir, exist_ok=True)
    cert = os.path.join(certdir, "cloud.crt")
    key = os.path.join(certdir, "cloud.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "30",
         "-subj", "/CN=cloud.lab"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def tls_server(port, cert, key, quiet):
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    log("cloud", f"TLS listening on {port}")

    def serve(raw, addr):
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except Exception:
            raw.close()
            return
        try:
            sni = getattr(conn, "server_hostname", None) or "-"
            if not quiet:
                log("cloud", f"TLS {addr[0]}:{addr[1]} -> :{port} sni={sni}")
            conn.settimeout(600)
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                # Echo a small ack, as a cloud service would.
                conn.sendall(b"\x00" * min(64, len(data)))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    while True:
        try:
            raw, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=serve, args=(raw, addr), daemon=True).start()


def http_server(port, quiet):
    """Plain HTTP, for modelling the cleartext-diagnostics finding."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    log("cloud", f"HTTP listening on {port}")

    def serve(conn, addr):
        try:
            conn.settimeout(10)
            req = conn.recv(8192).decode("latin-1", "replace")
            first = req.split("\r\n")[0] if req else ""
            if not quiet and first:
                log("cloud", f"HTTP {addr[0]} {first[:120]}")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Server: lab-cloud\r\n\r\nok")
        except Exception:
            pass
        finally:
            conn.close()

    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        threading.Thread(target=serve, args=(conn, addr), daemon=True).start()


def ntp_server(quiet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 123))
    log("cloud", "NTP listening on 123")
    while True:
        try:
            data, addr = sock.recvfrom(256)
        except OSError:
            continue
        now = int(time.time()) + NTP_EPOCH_DELTA
        resp = bytearray(48)
        resp[0] = 0x24
        resp[1] = 1
        struct.pack_into(">I", resp, 40, now)
        sock.sendto(bytes(resp), addr)
        if not quiet:
            log("cloud", f"NTP {addr[0]}")


def run_cloud(args):
    cert, key = ensure_cert()
    for port in config.CLOUD_TLS_PORTS:
        threading.Thread(target=tls_server,
                         args=(port, cert, key, args.quiet),
                         daemon=True).start()
    threading.Thread(target=http_server,
                     args=(config.CLOUD_HTTP_PORT, args.quiet),
                     daemon=True).start()
    threading.Thread(target=ntp_server, args=(args.quiet,), daemon=True).start()
    while True:
        time.sleep(3600)


# --------------------------------------------------------------------------
# Controller (hub stand-in)
# --------------------------------------------------------------------------

def run_controller(args):
    """Receive device reports, and subscribe outbound to each device.

    The outbound subscribe is what creates the router's conntrack entry; the
    device's reply is only allowed back while that entry lives. Raising
    --subscribe-interval above the router's UDP timeout reproduces the
    Matter-report drop.
    """
    stats = {}
    lock = threading.Lock()

    def listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 5540))
        log("controller", "listening on UDP 5540")
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                obj = json.loads(data)
                if obj.get("op") == "subscribe":
                    continue
                name = obj.get("device", addr[0])
            except Exception:
                name = addr[0]
            now = time.time()
            with lock:
                st = stats.setdefault(name, {"n": 0, "last": None, "gaps": []})
                if st["last"]:
                    st["gaps"].append(now - st["last"])
                st["n"] += 1
                st["last"] = now
            if not args.quiet:
                log("controller", f"report {name} from {addr[0]}:{addr[1]} "
                                  f"{len(data)}B")

    def subscribe():
        targets = [t.strip() for t in args.subscribe.split(",") if t.strip()]
        if not targets:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log("controller", f"subscribing to {targets} every "
                          f"{args.subscribe_interval:.0f}s")
        while True:
            for t in targets:
                try:
                    sock.sendto(b'{"op":"subscribe"}', (t, 5540))
                except Exception as e:
                    log("controller", f"subscribe {t} failed: {e}")
            time.sleep(args.subscribe_interval)

    def summary():
        while True:
            time.sleep(args.summary_interval)
            with lock:
                if not stats:
                    log("controller", "no reports yet")
                    continue
                log("controller", "--- report summary ---")
                for name, st in sorted(stats.items()):
                    g = sorted(st["gaps"])
                    if g:
                        over = sum(1 for x in st["gaps"] if x > 180)
                        print(f"    {name}: n={st['n']} "
                              f"median_gap={g[len(g)//2]:.1f}s "
                              f"max={g[-1]:.1f}s gaps>180s={over}", flush=True)
                    else:
                        print(f"    {name}: n={st['n']}", flush=True)

    threading.Thread(target=listen, daemon=True).start()
    threading.Thread(target=subscribe, daemon=True).start()
    threading.Thread(target=summary, daemon=True).start()
    while True:
        time.sleep(3600)


# --------------------------------------------------------------------------
# Plain TCP listeners, so the prober has something to find
# --------------------------------------------------------------------------

def run_listen(args):
    ports = [int(p) for p in args.ports.split(",") if p.strip()]

    def one(port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", port))
            srv.listen(16)
        except OSError as e:
            log("listen", f"port {port}: {e}")
            return
        while True:
            try:
                conn, _ = srv.accept()
                conn.sendall(b"lab-service\n")
                conn.close()
            except OSError:
                return

    for p in ports:
        threading.Thread(target=one, args=(p,), daemon=True).start()
    log("listen", f"open TCP ports: {ports}")
    while True:
        time.sleep(3600)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)

    r = sub.add_parser("resolver")
    r.add_argument("--query-log", default="")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=run_resolver)

    c = sub.add_parser("cloud")
    c.add_argument("--quiet", action="store_true")
    c.set_defaults(fn=run_cloud)

    h = sub.add_parser("controller")
    h.add_argument("--subscribe", default="")
    h.add_argument("--subscribe-interval", type=float, default=60.0)
    h.add_argument("--summary-interval", type=float, default=300.0)
    h.add_argument("--quiet", action="store_true")
    h.set_defaults(fn=run_controller)

    l = sub.add_parser("listen")
    l.add_argument("ports")
    l.set_defaults(fn=run_listen)

    args = ap.parse_args()
    try:
        args.fn(args)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
