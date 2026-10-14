#!/bin/sh
# Run Zeek over every capture; VLAN-tagged frames (VLAN 114, out of scope) are excluded by BPF.
set -e
cd "$(dirname "$0")/.."
ZEEK=/opt/zeek/bin/zeek
for pc in 2026*/wl0.2_*.pcap 2026*/eth7_*.pcap; do
    cap=$(dirname "$pc" | sed 's/^[0-9-]*_//'); ifc=$(basename "$pc" | cut -d_ -f1)
    out="derived/zeek/${cap}_${ifc}"; rm -rf "$out"; mkdir -p "$out"
    ( cd "$out" && $ZEEK -C -r "../../../$pc" -f 'not vlan' "../../../tools/zeek/iot-local.zeek" ) 2> "$out/zeek_stderr.txt"
    echo "$out: $(ls "$out" | tr '\n' ' ')"
done
