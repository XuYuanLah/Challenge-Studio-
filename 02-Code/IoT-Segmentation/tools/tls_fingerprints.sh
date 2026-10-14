#!/bin/sh
# JA4/JA3 + SNI of every TLS ClientHello per capture (tshark 4.4); VLAN-tagged frames excluded.
cd "$(dirname "$0")/.."; mkdir -p derived/tls; out=derived/tls/clienthello_fingerprints.tsv
printf 'capture\tframe_time_epoch\teth_src\tip_src\tip_dst\ttcp_dstport\tsni\tja4\tja3\n' > "$out"
for pc in 2026*/*.pcap; do
  tshark -r "$pc" -Y 'tls.handshake.type==1 && !vlan' -T fields -e frame.time_epoch -e eth.src -e ip.src -e ip.dst -e tcp.dstport \
    -e tls.handshake.extensions_server_name -e tls.handshake.ja4 -e tls.handshake.ja3 2>/dev/null | sed "s|^|$pc\t|" >> "$out"
done
echo "$(($(wc -l < "$out")-1)) ClientHellos -> $out"
