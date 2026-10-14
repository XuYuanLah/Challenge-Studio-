#!/bin/sh
# Re-provision the analysis toolchain after a terminal reset (Debian 13, arm64/amd64).
set -e
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark nmap jq iproute2 dnsutils iputils-ping curl gnupg tcpdump
if [ ! -x /opt/zeek/bin/zeek ]; then
  curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_13/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
  echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list >/dev/null
  sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zeek-8.0
fi
tshark --version | head -1; /opt/zeek/bin/zeek --version; nmap --version | head -1
