# iotpipe Zeek site policy (copied from tools/zeek/iot-local.zeek). Adapt Site::local_nets to your own
# address plan; mac-logging is required (iotpipe attributes connections to devices by MAC).
# Zeek site policy for the IoT segmentation analysis (offline pcap runs)
@load base/frameworks/notice
@load policy/protocols/conn/mac-logging        # orig/resp L2 addresses in conn.log (device attribution)
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/known-certs
@load policy/protocols/dns/detect-external-names
@load policy/frameworks/software/vulnerable
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/http/software-browser-plugins

redef LogAscii::use_json = T;                   # Splunk-friendly
redef ignore_checksums = T;                     # captured on the router: offload-mangled checksums
redef Site::local_nets += { 192.168.0.0/16, [fd00::]/8, [fe80::]/10 };
redef Known::use_host_store = F;
redef Known::use_service_store = F;
redef Known::use_cert_store = F;
