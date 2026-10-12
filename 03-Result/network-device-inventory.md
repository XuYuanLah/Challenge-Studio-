# Network device inventory

Capture window: **6 October 2026 21:53:27 – 7 October 2026 21:53:28 AEDT**. Both captures were inspected in full: eth7 **958,030** packets; wl0.2 **858,199** packets. The logs report zero kernel drops.

**31 distinct unicast Ethernet MAC addresses**, plus **5 additional identifiers in LLDP/DHCPv6** and **113 multicast/broadcast destination MACs**. The active MAC count includes multiple interfaces of the ASUS router. It is not a count of physical devices.

The two device tables classify by function. **The default network (192.168.0.x) is the owner’s personal network; VLAN 114 (192.168.114.x) is the guest / roommate network**, as confirmed by the owner. wl0.2 is the IoT VAP; eth7 is connected to the Hue bridge. Network placement identifies the network’s purpose, not the ownership of each individual device. Broadcast/multicast LAN traffic and VLAN 114 traffic appear in these captures, so presence in a capture is not proof of physical attachment to that interface. Private MACs cannot be resolved through an OUI; vendor names below distinguish host brand from network-interface vendor. Names and IPs describe the capture period, not current leases.

## Smart home / IoT

| MAC | IPv4 | Network | Hostname / advertised name | Vendor | Derived device type | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ec:b5:fa:bc:52:10 | 192.168.0.50 | Personal (default network) | ecb5fabc5210.local / Hue Bridge - BC5210 | Philips Lighting / Signify | Hue Bridge BSB002; Matter bridge | High | DHCP + ARP + mDNS modelid=BSB002 + Hue SSDP; user confirms eth7 connection |
| 0c:4e:a0:30:22:54 | 192.168.0.48 | Personal (default network) | SwitchBot-Hub-2-302254 / 0C4EA0302254.local | Espressif radio; SwitchBot product | SwitchBot Hub 2; Matter hub | High | DHCP product name + Matter advertisement + AWS IoT traffic |
| 7c:f1:7e:10:03:a0 | 192.168.0.207 | Personal (default network) | P110M / 7CF17E1003A0.local | TP-Link / Tapo | P110M smart plug; Matter, energy monitoring | High | DHCP P110M + Matter advertisement + tplinkcloud.com |
| 8c:87:d0:09:0d:6e | 192.168.0.19 | Personal (default network) | wlan0 / 8C87D0090D6E.local | Zemismart product; Shenzhen Uascent network hardware | Zemismart Matter wall switch; exact model unknown | User-confirmed device type; capture-confirmed Matter | User identifies both wlan0 devices as Zemismart wall switches; ARP + DHCP wlan0 + _matter._tcp + UDP 5540 exchanges with HomePod |
| 8c:87:d0:09:0d:6b | 192.168.0.21 | Personal (default network) | wlan0 / 8C87D0090D6B.local | Zemismart product; Shenzhen Uascent network hardware | Zemismart Matter wall switch; exact model unknown | User-confirmed device type; capture-confirmed Matter | User identifies both wlan0 devices as Zemismart wall switches; ARP + DHCP wlan0 + _matter._tcp + UDP 5540 exchanges with HomePod |
| ac:bc:b5:d3:d1:dd | 192.168.0.22 | Personal (default network) | HomePod-2nd-Gen.local | Apple | HomePod 2nd generation; smart speaker / Thread border router | High | DHCP + AirPlay AudioAccessory6,1 + _meshcop._udp + HomePodSensor + proxied Eve Room |
| d8:3a:dd:dd:7f:61 | 192.168.0.8 | Personal (default network) | raspberry-pi.local / Homebridge F416 342D | Raspberry Pi Trading | Raspberry Pi running Homebridge; also local DNS server | High | Homebridge HAP TXT md=homebridge; _smb; answers DNS requests from Hue/SwitchBot/Tapo |
| cc:b8:5e:82:fa:10 | 192.168.114.25 | Guest / roommate (VLAN 114) | Not advertised | Shenzhen Phaten Tech; Tuya platform | Tuya smart device; exact appliance unknown | High: Tuya; Unknown: appliance | VLAN 114; decoded UDP 6667 discovery confirms IP, productKey=jmogl0y6dmkdkcew, protocol 3.3 |

**Additional IoT device advertised through the HomePod:** Eve Room 2F41, model **Eve Room 20EBX9901**, host **Eve-Room-2F41.local**, HAP/CoAP UDP **5683**. Its Ethernet/Wi-Fi MAC is not exposed; the HomePod advertises it on behalf of the Thread device. IPv6 addresses: `fdbb:82f8:256f:0:ec71:ce06:3eb9:7355`, `fdbb:82f8:256f:0:e1ea:b043:aea8:a393`, `fdbb:82f8:256f:0:5327:157a:72a5:413c`. **Owner context:** a new Eve Room may have been added/reset during this capture. That setup/reset activity is a plausible explanation for the changing HomeKit pairing IDs and Thread IPv6 addresses. The captures do not prove that causal link or establish a physical-device count from these changes; treat the records as a changing advertised identity rather than count each pairing ID/address as another sensor. The HomePod also advertises its own HomePodSensor 184622; that is a service of the HomePod.

## Other devices and network infrastructure

| MAC | IPv4 | Network | Hostname / advertised name | Vendor | Derived device type | Confidence | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| cc:28:aa:2b:39:60 | 192.168.0.1 | Personal (default network) | RT-BE88U | ASUSTeK | Main router / LAN bridge | High | ARP gateway + LLDP SysN=RT-BE88U + AsusWRT UPnP; forwards cloud traffic |
| 90:28:aa:2b:39:62 | Not exposed | Router infrastructure; VLAN/IP not exposed | RT-BE88U-associated interface | ASUS-associated; no match in local vendor DB | Router radio/interface alias | Medium | wl0.2-only; Broadcom 0x886c control traffic; related suffix to confirmed router interface |
| 92:28:aa:2b:39:62 | Not exposed | Router infrastructure; VLAN/IP not exposed | RT-BE88U | Locally administered; ASUS from LLDP | Router IoT VAP / bridge interface | High | wl0.2; LLDP names RT-BE88U, STP root is cc:28:aa:2b:39:60; EAPOL group keys |
| ce:28:aa:2b:39:60 | Not exposed | Router infrastructure; VLAN/IP not exposed | RT-BE88U-associated interface | Locally administered; ASUS inferred | Router virtual/control interface alias | Medium | wl0.2-only; Broadcom 0x886c control traffic; local-bit variant of cc:28:aa:2b:39:60 |
| 94:83:c4:5f:15:23 | 192.168.0.20 | Personal (default network) | GL-AR300M | GL Technologies / GL.iNet | GL-AR300M travel router / bridge | High | ARP + DHCP GL-AR300M; udhcp 1.35.0 |
| 6c:a6:04:b5:39:28 | 192.168.0.15 | Personal (default network) | ext.local / W6UB53928 | CommScope / ARRIS | SURFboard W6U Wi-Fi 6E adapter / extender | High | mDNS _arris: modelname=W6U, devname=W6UB53928, joined=1 |
| e0:46:ee:3a:53:ec | 192.168.0.10 | Personal (default network) | Not advertised | NETGEAR | MS510T-series managed switch; exact suffix unknown | High: switch; Medium: family | SSDP Server: Netgear_Switch UPnP/1.1 MS510TXXX/2.2.2; ARP |
| 84:e5:d8:e1:83:3b | 192.168.0.9 | Personal (default network) | Not advertised | Guangdong UNIPOE IoT Technology | Likely managed Ethernet / PoE switch | Medium | ARP + DHCP ACK for .9; continuous Realtek 0x8899 Layer-2 management broadcasts |
| 80:3f:5d:75:81:68 | No IPv4 observed | Guest / roommate (VLAN 114) | WL-WN586X3 | Winstars / WAVLINK | WL-WN586X3 Wi-Fi router | High: model; mode unknown | VLAN 114; DHCPv6 FQDN WL-WN586X3; link-local source; requested fd00:d:e:72::2 with zero lifetime |
| bc:89:c1:d9:60:9c | 192.168.0.2 | Personal (default network) | Mac-Studio.local | Apple | Mac Studio; advertised model Mac17,14 | High | ARP + mDNS named device-info record; AirPlay / SMB / VNC |
| 88:c9:b3:be:f5:3f | 192.168.0.4 | Personal (default network) | i0nTempests-MacBook-Pro.local (DHCP: i0nTempests-MBP) | MMUI network interface; Apple host | MacBook Pro; advertised model Mac16,1 | High | DHCP + mDNS named device-info; vendor prefix is MA-M 88:C9:B3:B/28 |
| c8:80:6d:30:8b:a4 | 192.168.0.13 | Personal (default network) | Mac-mini-Server.local | Apple | Mac mini server; advertised model Mac18,5 | High | DHCP + mDNS device-info; SMB, SSH, VNC, Time Machine, shared printer |
| 00:90:27:f5:71:0e | 192.168.0.14 | Personal (default network) | iKOOLCORE-R2.local | Intel network interface; iKOOLCORE inferred from hostname | iKOOLCORE R2 computer / mini PC | High: name/IP; Medium: hardware | mDNS A record .14 + ARP; NBNS ASUS-PC occurs as queries and is not assigned as this host name |
| 88:c9:b3:b3:26:e4 | 192.168.0.16 | Personal (default network) | MSI-Portable.local | MMUI network interface; MSI inferred from hostname | Windows portable computer | High | DHCP MSFT 5.0 + hostname + Windows HTTP user agent + mDNS _dosvc |
| 08:bf:b8:6d:b3:91 | 192.168.0.17 | Personal (default network) | ASUS-PC.local / ASUS-PC-2.local | ASUSTeK | Windows PC | High | DHCP MSFT 5.0 + NBNS registration + Windows HTTP user agents |
| 50:eb:f6:b5:3b:b7 | 192.168.114.5 | Guest / roommate (VLAN 114) | DESKTOP-541ILVL.local | ASUSTeK | Windows PC on VLAN 114 | High | VLAN 114 + DHCP MSFT 5.0 + mDNS _dosvc + Windows Chromium user agent |
| 00:0c:29:43:00:83 | 192.168.0.154 | Personal (default network) | Linux.local | VMware | Linux virtual machine | High | VMware MAC + DHCP Linux + mDNS A record |
| 00:0c:29:d4:b3:5c | 192.168.0.182 | Personal (default network) | Windows / WINDOWS | VMware | Windows virtual machine | High | VMware MAC + DHCP MSFT 5.0 + NBNS registrations; temporary 169.254.154.118 also seen |
| 94:89:78:84:87:43 | 192.168.0.221 | Personal (default network) | i0nTempests-iPhone-17-Pro.local | Apple | iPhone 17 Pro (name-derived) | High: iPhone; Medium: model | DHCP name i0nTempone17Pro + Apple mobile-device advertisements + mDNS host name |
| 4e:a0:14:c6:42:f6 | 192.168.0.225 | Personal (default network) | i0nTempest-s-Pixel-9a / Android_4K2WTTWX.local / Android_5GM5TJV0.local | Private MAC; Google from device TXT | Google Pixel 9a Android phone | High | DHCP android-dhcp-17 + mDNS TXT name=Pixel 9a + ADB services |
| 3a:4d:a3:60:43:1a | 192.168.0.73 | Personal (default network) | Watch | Private MAC; likely Apple | Wearable; likely Apple Watch | High: name/IP; Medium: Apple Watch | DHCP Watch + ARP; private MAC prevents vendor OUI resolution |
| 04:68:65:53:fa:43 | 192.168.114.6 | Guest / roommate (VLAN 114) | andrewtkiiPhone | Apple | iPhone on VLAN 114 | High | DHCP host name + Apple OUI + tagged VLAN 114 |
| 9e:6a:9c:71:52:df | 192.168.114.13 | Guest / roommate (VLAN 114) | SeandeMacBook-Air.local / Sean的MacBook Air (DHCP: Mac) | Private MAC; Apple from device TXT | MacBook Air; advertised model Mac15,12 | High | VLAN 114 + mDNS device-info model + service name + DHCP |

## Interpretation and unresolved details

- **Owner-confirmed correction:** the wlan0 devices at 192.168.0.19 (8c:87:d0:09:0d:6e) and 192.168.0.21 (8c:87:d0:09:0d:6b) are **Zemismart Matter wall switches** on the personal network. Uascent is the network-hardware vendor identified from the MAC prefix; Zemismart is the product brand supplied by the owner. Exact model numbers remain undisclosed.
- The Tuya device is conclusively identified by its decoded discovery broadcast: protocol 3.3, product key `jmogl0y6dmkdkcew`, IP .114.25. The broadcast does not expose a human-readable model, so a plug, light or another appliance cannot be chosen reliably.
- The UNIPOE device .9 is probably a switch based on its network-equipment vendor and continuous Realtek L2 management traffic; no model or hostname was provided.
- wl0.2 bidirectional traffic strongly supports attachment for SwitchBot, Tapo, both Zemismart wall switches and the HomePod. Hue has bidirectional traffic on eth7. The Tuya device is seen broadcasting on tagged VLAN 114, the guest / roommate network, in eth7.
- Network-infrastructure equipment is in the other table even where its manufacturer name contains “IoT”. The Watch and phones are personal devices. Homebridge belongs in IoT because its advertised function is a smart-home bridge.
- The router’s MAC also carries packets with internet-source IPs; those addresses do not belong to the router. Likewise DNS answers from the Raspberry Pi are not its own addresses, and Thread addresses advertised by the HomePod are not all HomePod addresses.
- Temporary IPv4 link-local addresses were also observed: ASUS-PC `169.254.167.190`; Windows VM `169.254.154.118`. `0.0.0.0`/`::` are unspecified acquisition addresses. An ARP claim for `87.121.248.55` used the router MAC, but that does not prove it is the router WAN address.
- No active scanning, reverse lookups against local devices, credential use or capture modification was performed.

## Additional MAC identifiers embedded in control protocols

These addresses are not additional observed Ethernet senders. A retained DHCPv6 client identifier can reference another or historical interface; it does not establish an IP lease for that embedded MAC.

| MAC identifier | Associated host | Meaning | Evidence |
| --- | --- | --- | --- |
| 9e:ea:c7:14:cd:5d | RT-BE88U | Router chassis / DHCPv6 server identifier | LLDP chassis ID and DHCPv6 server DUID; relates to cc:28:aa:2b:39:60; management address 127.0.1.1 is loopback |
| 00:0c:29:d4:b3:52 | Windows VM | VMware retained DUID MAC | Embedded in client DUID of active 00:0c:29:d4:b3:5c; no frames from this MAC |
| 08:bf:b8:6d:b3:90 | ASUS-PC | ASUS retained DUID MAC | Embedded in client DUID of active 08:bf:b8:6d:b3:91; no frames from this MAC |
| 5e:1b:83:b4:bc:05 | andrewtkiiPhone | Private retained DUID MAC | Embedded in client DUID of active 04:68:65:53:fa:43; no frames from this MAC |
| 06:86:05:37:9e:44 | i0nTempests-MacBook-Pro | Private retained DUID MAC | Embedded in client DUID of active 88:c9:b3:be:f5:3f; no frames from this MAC |

## IPv6 addresses for primary devices

These combine own-host mDNS address records with observed link-local packet sources. Requested DHCPv6 leases are separate and are not asserted to have been granted.

| MAC | Host | IPv6 |
| --- | --- | --- |
| ec:b5:fa:bc:52:10 | ecb5fabc5210.local / Hue Bridge - BC5210 | 2404:e80:5346:0:eeb5:faff:febc:5210; fd00:d:e:f:eeb5:faff:febc:5210; fe80::eeb5:faff:febc:5210 |
| 0c:4e:a0:30:22:54 | SwitchBot-Hub-2-302254 / 0C4EA0302254.local | fe80::e4e:a0ff:fe30:2254 |
| 7c:f1:7e:10:03:a0 | P110M / 7CF17E1003A0.local | 2404:e80:5346:0:7ef1:7eff:fe10:3a0; fd00:d:e:f:7ef1:7eff:fe10:3a0; fe80::7ef1:7eff:fe10:3a0 |
| 8c:87:d0:09:0d:6e | wlan0 / 8C87D0090D6E.local | 2404:e80:5346:0:8e87:d0ff:fe09:d6e; fd00:d:e:f:8e87:d0ff:fe09:d6e; fe80::8e87:d0ff:fe09:d6e |
| 8c:87:d0:09:0d:6b | wlan0 / 8C87D0090D6B.local | 2404:e80:5346:0:8e87:d0ff:fe09:d6b; fd00:d:e:f:8e87:d0ff:fe09:d6b; fe80::8e87:d0ff:fe09:d6b |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | 2404:e80:5346:0:30fa:e82e:539c:51b6; 2404:e80:5346:0:3550:6ef3:8867:8772; 2404:e80:5346:0:496d:ac0d:c2f6:ece5; 2404:e80:5346:0:59a6:c01a:b76e:ce0d; 2404:e80:5346:0:6838:70c7:833:8ca4; 2404:e80:5346:0:7c46:7705:602f:acd7; 2404:e80:5346:0:90e6:3b22:39f2:aa9f; 2404:e80:5346:0:b16a:a413:2b2e:3d14; 2404:e80:5346:0:cda:7fd1:d4cf:8f2b; fd00:d:e:f:183e:4f13:4044:5684; fd00:d:e:f::61; fe80::1491:5d3e:91a9:266e; fe80::1887:20b7:1b7:b54 |
| d8:3a:dd:dd:7f:61 | raspberry-pi.local / Homebridge F416 342D | 2404:e80:5346:0:d27a:d211:34e0:c075; fd00:d:e:f::8; fd00:d:e:f:d0c0:521b:86a9:e914; fe80::ee49:878f:97d4:9850 |
| cc:b8:5e:82:fa:10 | Not advertised | Not exposed |
| cc:28:aa:2b:39:60 | RT-BE88U | fe80::ce28:aaff:fe2b:3960 |
| 90:28:aa:2b:39:62 | RT-BE88U-associated interface | Not exposed |
| 92:28:aa:2b:39:62 | RT-BE88U | Not exposed |
| ce:28:aa:2b:39:60 | RT-BE88U-associated interface | Not exposed |
| 94:83:c4:5f:15:23 | GL-AR300M | Not exposed |
| 6c:a6:04:b5:39:28 | ext.local / W6UB53928 | fd05:37e5:64c4::1; fe80::6ea6:4ff:feb5:3928 |
| e0:46:ee:3a:53:ec | Not advertised | fe80::e246:eeff:fe3a:53ec |
| 84:e5:d8:e1:83:3b | Not advertised | Not exposed |
| 80:3f:5d:75:81:68 | WL-WN586X3 | fe80::823f:5dff:fe75:8168 |
| bc:89:c1:d9:60:9c | Mac-Studio.local | 2404:e80:5346:0:1475:e34:f28d:73ad; fd00:d:e:f:1c6b:3f9c:ab3a:5e30; fd00:d:e:f::2; fe80::62:bb67:c1e:4a64 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local (DHCP: i0nTempests-MBP) | 2404:e80:5346:0:64:5c07:a0b9:a2b4; fd00:d:e:f:40a:59f0:5fbc:8961; fd00:d:e:f::4; fe80::1425:c2ee:dbaf:508 |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | 2404:e80:5346:0:1012:e075:8f71:9273; fd00:d:e:f:182e:904d:73e0:e57b; fd00:d:e:f::13; fe80::cb9:fa07:520e:7ece |
| 00:90:27:f5:71:0e | iKOOLCORE-R2.local | fe80::1c18:ac39:3a4a:8017 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | 2404:e80:5346:0:18ab:a9f4:8209:dbb3; 2404:e80:5346:0:4508:797d:cc5c:e636; fd00:d:e:f:18ab:a9f4:8209:dbb3; fd00:d:e:f:24d:8a29:389a:4223; fd00:d:e:f::a6; fe80::a482:550c:40be:3da4 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local / ASUS-PC-2.local | 2404:e80:5346:0:296c:2226:4a9c:5162; 2404:e80:5346:0:5de6:6453:8a21:c7c5; 2404:e80:5346:0:e9b2:c2f7:4d2:3d20; fd00:d:e:f:5de6:6453:8a21:c7c5; fd00:d:e:f::87; fd00:d:e:f:cef3:e5ee:7177:9a4b; fd00:d:e:f:e9b2:c2f7:4d2:3d20; fe80::286:cf6f:e629:459a |
| 50:eb:f6:b5:3b:b7 | DESKTOP-541ILVL.local | fd00:d:e:72::6; fe80::3486:e60b:f45b:cc6d |
| 00:0c:29:43:00:83 | Linux.local | 2404:e80:5346:0:a28c:f260:138f:acd8; fd00:d:e:f:940d:4e49:7af3:8ad2; fd00:d:e:f::16; fe80::23df:7822:a95f:2a5a |
| 00:0c:29:d4:b3:5c | Windows / WINDOWS | fe80::a3fd:c7bb:74c2:6980 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | 2404:e80:5346:0:55:c71e:5752:4b11; fd00:d:e:f:14f2:f20c:aaec:c129; fd00:d:e:f::77; fe80::14a6:f09a:f112:2ee1; fe80::4a:e64a:b7ef:9b3d |
| 4e:a0:14:c6:42:f6 | i0nTempest-s-Pixel-9a / Android_4K2WTTWX.local / Android_5GM5TJV0.local | 2404:e80:5346:0:4ca0:14ff:fec6:42f6; fd00:d:e:f:4ca0:14ff:fec6:42f6; fe80::4ca0:14ff:fec6:42f6 |
| 3a:4d:a3:60:43:1a | Watch | fe80::c3a:fc59:a270:c471 |
| 04:68:65:53:fa:43 | andrewtkiiPhone | fe80::815:c668:266d:706a; fe80::83b:a1f4:183c:8e68; fe80::ae:23f7:8de7:fdf0 |
| 9e:6a:9c:71:52:df | SeandeMacBook-Air.local / Sean的MacBook Air (DHCP: Mac) | fd00:d:e:72::13; fe80::c9f:ced:40d8:94ae |

## Addresses referenced in DHCPv6 client requests

A request/renewal/confirmation is not a server lease grant. In particular the Wavlink request carries a zero valid lifetime. These entries are preserved separately from observed or advertised addresses.

| Ethernet sender MAC | Requested/referenced IPv6 address(es) |
| --- | --- |
| 00:0c:29:d4:b3:5c | fd00:d:e:f::43 |
| 00:90:27:f5:71:0e | fd00:d:e:f::14 |
| 04:68:65:53:fa:43 | fd00:d:e:72::14 |
| 08:bf:b8:6d:b3:91 | fd00:d:e:f::87 |
| 3a:4d:a3:60:43:1a | fd00:d:e:f::53 |
| 4e:a0:14:c6:42:f6 | 2404:e80:5346:0:4ca0:14ff:fec6:42f6; 2404:e80:5346:0:8ee5:6e16:64e:a45f; 2404:e80:5346:0:c7e5:8de3:1be2:eddb; fd00:d:e:f:4ca0:14ff:fec6:42f6; fd00:d:e:f:778c:a734:9e87:2de9; fd00:d:e:f:bb5f:8a68:9117:2c11 |
| 50:eb:f6:b5:3b:b7 | fd00:d:e:72::6 |
| 80:3f:5d:75:81:68 | fd00:d:e:72::2 |
| 88:c9:b3:b3:26:e4 | fd00:d:e:f::a6 |
| 88:c9:b3:be:f5:3f | fd00:d:e:f::4 |
| 94:89:78:84:87:43 | fd00:d:e:f::77 |
| 9e:6a:9c:71:52:df | fd00:d:e:72::13 |
| ac:bc:b5:d3:d1:dd | fd00:d:e:f::61 |
| bc:89:c1:d9:60:9c | fd00:d:e:f::2 |
| c8:80:6d:30:8b:a4 | fd00:d:e:f::13 |
| d8:3a:dd:dd:7f:61 | fd00:d:e:f::8 |
| e0:46:ee:3a:53:ec | fd00:d:e:f::68 |

## Complete local mDNS address records

The “advertiser MAC” may be a proxy or border router. Treat each record owner as the host to which the advertised address belongs.

| Advertiser MAC | Record owner | Address |
| --- | --- | --- |
| 00:0c:29:43:00:83 | Linux.local | 192.168.0.154 |
| 00:0c:29:43:00:83 | Linux.local | 2404:e80:5346:0:a28c:f260:138f:acd8 |
| 00:0c:29:43:00:83 | Linux.local | fd00:d:e:f:940d:4e49:7af3:8ad2 |
| 00:0c:29:43:00:83 | Linux.local | fd00:d:e:f::16 |
| 00:0c:29:43:00:83 | Linux.local | fe80::23df:7822:a95f:2a5a |
| 00:90:27:f5:71:0e | iKOOLCORE-R2.local | 192.168.0.14 |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | 192.168.0.17 |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | 2404:e80:5346:0:296c:2226:4a9c:5162 |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | 2404:e80:5346:0:e9b2:c2f7:4d2:3d20 |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | fd00:d:e:f:cef3:e5ee:7177:9a4b |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | fd00:d:e:f:e9b2:c2f7:4d2:3d20 |
| 08:bf:b8:6d:b3:91 | ASUS-PC-2.local | fe80::286:cf6f:e629:459a |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | 192.168.0.17 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | 2404:e80:5346:0:296c:2226:4a9c:5162 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | 2404:e80:5346:0:5de6:6453:8a21:c7c5 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | 2404:e80:5346:0:e9b2:c2f7:4d2:3d20 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | fd00:d:e:f:5de6:6453:8a21:c7c5 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | fd00:d:e:f::87 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | fd00:d:e:f:cef3:e5ee:7177:9a4b |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | fd00:d:e:f:e9b2:c2f7:4d2:3d20 |
| 08:bf:b8:6d:b3:91 | ASUS-PC.local | fe80::286:cf6f:e629:459a |
| 0c:4e:a0:30:22:54 | 0C4EA0302254.local | 192.168.0.48 |
| 0c:4e:a0:30:22:54 | 0C4EA0302254.local | fe80::e4e:a0ff:fe30:2254 |
| 4e:a0:14:c6:42:f6 | Android_4K2WTTWX.local | 192.168.0.225 |
| 4e:a0:14:c6:42:f6 | Android_4K2WTTWX.local | 2404:e80:5346:0:4ca0:14ff:fec6:42f6 |
| 4e:a0:14:c6:42:f6 | Android_4K2WTTWX.local | fd00:d:e:f:4ca0:14ff:fec6:42f6 |
| 4e:a0:14:c6:42:f6 | Android_4K2WTTWX.local | fe80::4ca0:14ff:fec6:42f6 |
| 4e:a0:14:c6:42:f6 | Android_5GM5TJV0.local | 192.168.0.225 |
| 4e:a0:14:c6:42:f6 | Android_5GM5TJV0.local | 2404:e80:5346:0:4ca0:14ff:fec6:42f6 |
| 4e:a0:14:c6:42:f6 | Android_5GM5TJV0.local | fd00:d:e:f:4ca0:14ff:fec6:42f6 |
| 4e:a0:14:c6:42:f6 | Android_5GM5TJV0.local | fe80::4ca0:14ff:fec6:42f6 |
| 50:eb:f6:b5:3b:b7 | DESKTOP-541ILVL.local | 192.168.114.5 |
| 50:eb:f6:b5:3b:b7 | DESKTOP-541ILVL.local | fd00:d:e:72::6 |
| 50:eb:f6:b5:3b:b7 | DESKTOP-541ILVL.local | fe80::3486:e60b:f45b:cc6d |
| 6c:a6:04:b5:39:28 | ext.local | 192.168.0.15 |
| 6c:a6:04:b5:39:28 | ext.local | fd05:37e5:64c4::1 |
| 7c:f1:7e:10:03:a0 | 7CF17E1003A0.local | 192.168.0.207 |
| 7c:f1:7e:10:03:a0 | 7CF17E1003A0.local | 2404:e80:5346:0:7ef1:7eff:fe10:3a0 |
| 7c:f1:7e:10:03:a0 | 7CF17E1003A0.local | fd00:d:e:f:7ef1:7eff:fe10:3a0 |
| 7c:f1:7e:10:03:a0 | 7CF17E1003A0.local | fe80::7ef1:7eff:fe10:3a0 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | 192.168.0.16 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | 2404:e80:5346:0:18ab:a9f4:8209:dbb3 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | 2404:e80:5346:0:4508:797d:cc5c:e636 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | fd00:d:e:f:18ab:a9f4:8209:dbb3 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | fd00:d:e:f:24d:8a29:389a:4223 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | fd00:d:e:f::a6 |
| 88:c9:b3:b3:26:e4 | MSI-Portable.local | fe80::a482:550c:40be:3da4 |
| 88:c9:b3:be:f5:3f | 5bd3ebc3-95b7-45a9-bf6f-fb2770c4599e.local | 192.168.0.4 |
| 88:c9:b3:be:f5:3f | 5bd3ebc3-95b7-45a9-bf6f-fb2770c4599e.local | 2404:e80:5346:0:64:5c07:a0b9:a2b4 |
| 88:c9:b3:be:f5:3f | 5bd3ebc3-95b7-45a9-bf6f-fb2770c4599e.local | fd00:d:e:f:40a:59f0:5fbc:8961 |
| 88:c9:b3:be:f5:3f | 5bd3ebc3-95b7-45a9-bf6f-fb2770c4599e.local | fd00:d:e:f::4 |
| 88:c9:b3:be:f5:3f | 5bd3ebc3-95b7-45a9-bf6f-fb2770c4599e.local | fe80::1425:c2ee:dbaf:508 |
| 88:c9:b3:be:f5:3f | bf7e6392-31c5-400c-b423-548b93609905.local | 192.168.0.4 |
| 88:c9:b3:be:f5:3f | bf7e6392-31c5-400c-b423-548b93609905.local | 2404:e80:5346:0:64:5c07:a0b9:a2b4 |
| 88:c9:b3:be:f5:3f | bf7e6392-31c5-400c-b423-548b93609905.local | fd00:d:e:f:40a:59f0:5fbc:8961 |
| 88:c9:b3:be:f5:3f | bf7e6392-31c5-400c-b423-548b93609905.local | fd00:d:e:f::4 |
| 88:c9:b3:be:f5:3f | bf7e6392-31c5-400c-b423-548b93609905.local | fe80::1425:c2ee:dbaf:508 |
| 88:c9:b3:be:f5:3f | c3d50233-5692-40d7-b982-062993330c43.local | 192.168.0.4 |
| 88:c9:b3:be:f5:3f | c3d50233-5692-40d7-b982-062993330c43.local | 2404:e80:5346:0:64:5c07:a0b9:a2b4 |
| 88:c9:b3:be:f5:3f | c3d50233-5692-40d7-b982-062993330c43.local | fd00:d:e:f:40a:59f0:5fbc:8961 |
| 88:c9:b3:be:f5:3f | c3d50233-5692-40d7-b982-062993330c43.local | fd00:d:e:f::4 |
| 88:c9:b3:be:f5:3f | c3d50233-5692-40d7-b982-062993330c43.local | fe80::1425:c2ee:dbaf:508 |
| 88:c9:b3:be:f5:3f | f780d3e4-6a58-4ec7-8b45-aed68867bb8d.local | 192.168.0.4 |
| 88:c9:b3:be:f5:3f | f780d3e4-6a58-4ec7-8b45-aed68867bb8d.local | 2404:e80:5346:0:64:5c07:a0b9:a2b4 |
| 88:c9:b3:be:f5:3f | f780d3e4-6a58-4ec7-8b45-aed68867bb8d.local | fd00:d:e:f:40a:59f0:5fbc:8961 |
| 88:c9:b3:be:f5:3f | f780d3e4-6a58-4ec7-8b45-aed68867bb8d.local | fd00:d:e:f::4 |
| 88:c9:b3:be:f5:3f | f780d3e4-6a58-4ec7-8b45-aed68867bb8d.local | fe80::1425:c2ee:dbaf:508 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local | 192.168.0.4 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local | 2404:e80:5346:0:64:5c07:a0b9:a2b4 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local | fd00:d:e:f:40a:59f0:5fbc:8961 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local | fd00:d:e:f::4 |
| 88:c9:b3:be:f5:3f | i0nTempests-MacBook-Pro.local | fe80::1425:c2ee:dbaf:508 |
| 8c:87:d0:09:0d:6b | 8C87D0090D6B.local | 192.168.0.21 |
| 8c:87:d0:09:0d:6b | 8C87D0090D6B.local | 2404:e80:5346:0:8e87:d0ff:fe09:d6b |
| 8c:87:d0:09:0d:6b | 8C87D0090D6B.local | fd00:d:e:f:8e87:d0ff:fe09:d6b |
| 8c:87:d0:09:0d:6b | 8C87D0090D6B.local | fe80::8e87:d0ff:fe09:d6b |
| 8c:87:d0:09:0d:6e | 8C87D0090D6E.local | 192.168.0.19 |
| 8c:87:d0:09:0d:6e | 8C87D0090D6E.local | 2404:e80:5346:0:8e87:d0ff:fe09:d6e |
| 8c:87:d0:09:0d:6e | 8C87D0090D6E.local | fd00:d:e:f:8e87:d0ff:fe09:d6e |
| 8c:87:d0:09:0d:6e | 8C87D0090D6E.local | fe80::8e87:d0ff:fe09:d6e |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | 192.168.0.221 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | 2404:e80:5346:0:55:c71e:5752:4b11 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | fd00:d:e:f:14f2:f20c:aaec:c129 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | fd00:d:e:f::77 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | fe80::14a6:f09a:f112:2ee1 |
| 94:89:78:84:87:43 | i0nTempests-iPhone-17-Pro.local | fe80::4a:e64a:b7ef:9b3d |
| 9e:6a:9c:71:52:df | 0333eb2f-b8da-48d1-940a-3d683acde441.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 0333eb2f-b8da-48d1-940a-3d683acde441.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 0333eb2f-b8da-48d1-940a-3d683acde441.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 1f477726-3ddd-4a68-8364-e1be89e9e650.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 1f477726-3ddd-4a68-8364-e1be89e9e650.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 1f477726-3ddd-4a68-8364-e1be89e9e650.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 210e01ed-791b-49a8-8765-a38a5f472223.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 210e01ed-791b-49a8-8765-a38a5f472223.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 210e01ed-791b-49a8-8765-a38a5f472223.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 26f6d36e-776f-4682-b09d-92b54b9fe593.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 26f6d36e-776f-4682-b09d-92b54b9fe593.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 26f6d36e-776f-4682-b09d-92b54b9fe593.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 2cf23008-c3b4-49d8-b34b-878203ae5fd5.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 2cf23008-c3b4-49d8-b34b-878203ae5fd5.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 2cf23008-c3b4-49d8-b34b-878203ae5fd5.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 48378d92-e526-42bd-b603-b3c8f2c5d9d3.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 48378d92-e526-42bd-b603-b3c8f2c5d9d3.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 48378d92-e526-42bd-b603-b3c8f2c5d9d3.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 4cebdbd2-5b6a-431a-b1cf-d4b8cbbc17b3.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 4cebdbd2-5b6a-431a-b1cf-d4b8cbbc17b3.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 4cebdbd2-5b6a-431a-b1cf-d4b8cbbc17b3.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 4d3729f6-a75c-455f-924a-2a7e7b6a3d49.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 4d3729f6-a75c-455f-924a-2a7e7b6a3d49.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 4d3729f6-a75c-455f-924a-2a7e7b6a3d49.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 4f8e14c0-97d4-418c-8a4d-de880b05160d.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 4f8e14c0-97d4-418c-8a4d-de880b05160d.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 4f8e14c0-97d4-418c-8a4d-de880b05160d.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 6e25906a-cc9e-47d7-809a-3fcd6b010308.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 6e25906a-cc9e-47d7-809a-3fcd6b010308.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 6e25906a-cc9e-47d7-809a-3fcd6b010308.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 6f495d29-f6be-4ac2-a221-0532a86bc89a.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 6f495d29-f6be-4ac2-a221-0532a86bc89a.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 6f495d29-f6be-4ac2-a221-0532a86bc89a.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 7431d0f3-6148-49b1-8ded-e6893e0e0682.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 7431d0f3-6148-49b1-8ded-e6893e0e0682.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 7431d0f3-6148-49b1-8ded-e6893e0e0682.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 76c70ca6-59ec-4ec5-85a1-e6d03bdc37c5.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 76c70ca6-59ec-4ec5-85a1-e6d03bdc37c5.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 76c70ca6-59ec-4ec5-85a1-e6d03bdc37c5.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 93b663f2-ff60-4653-8226-34bd396da8f6.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 93b663f2-ff60-4653-8226-34bd396da8f6.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 93b663f2-ff60-4653-8226-34bd396da8f6.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | 986c08ce-c819-41cc-b057-2dbd85858b0d.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | 986c08ce-c819-41cc-b057-2dbd85858b0d.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | 986c08ce-c819-41cc-b057-2dbd85858b0d.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | SeandeMacBook-Air.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | SeandeMacBook-Air.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | SeandeMacBook-Air.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | b9a36447-a9f2-4183-883c-24d4281d4d40.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | b9a36447-a9f2-4183-883c-24d4281d4d40.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | b9a36447-a9f2-4183-883c-24d4281d4d40.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | bc196140-a518-4ac1-80e5-43c79e46ad1a.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | bc196140-a518-4ac1-80e5-43c79e46ad1a.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | bc196140-a518-4ac1-80e5-43c79e46ad1a.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | c65da92a-63f2-4a35-b12d-bba46c775f87.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | c65da92a-63f2-4a35-b12d-bba46c775f87.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | c65da92a-63f2-4a35-b12d-bba46c775f87.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | ddba815b-18c5-4d07-a2c7-aabf16822762.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | ddba815b-18c5-4d07-a2c7-aabf16822762.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | ddba815b-18c5-4d07-a2c7-aabf16822762.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | e83025e7-4775-4e5d-855d-36b2032c11f9.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | e83025e7-4775-4e5d-855d-36b2032c11f9.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | e83025e7-4775-4e5d-855d-36b2032c11f9.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | edd1a8e4-af82-45d9-b8f9-75100839875b.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | edd1a8e4-af82-45d9-b8f9-75100839875b.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | edd1a8e4-af82-45d9-b8f9-75100839875b.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | f0578013-a7de-4cfb-808a-bf019253ddf2.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | f0578013-a7de-4cfb-808a-bf019253ddf2.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | f0578013-a7de-4cfb-808a-bf019253ddf2.local | fe80::c9f:ced:40d8:94ae |
| 9e:6a:9c:71:52:df | f80bfaa8-9f81-4438-b3aa-0ad8c1233514.local | 192.168.114.13 |
| 9e:6a:9c:71:52:df | f80bfaa8-9f81-4438-b3aa-0ad8c1233514.local | fd00:d:e:72::13 |
| 9e:6a:9c:71:52:df | f80bfaa8-9f81-4438-b3aa-0ad8c1233514.local | fe80::c9f:ced:40d8:94ae |
| ac:bc:b5:d3:d1:dd | 1ADEBADCB8D4.local | 2404:e80:5346:0:7c46:7705:602f:acd7 |
| ac:bc:b5:d3:d1:dd | 1ADEBADCB8D4.local | 2404:e80:5346:0:cda:7fd1:d4cf:8f2b |
| ac:bc:b5:d3:d1:dd | 1ADEBADCB8D4.local | fd00:d:e:f:183e:4f13:4044:5684 |
| ac:bc:b5:d3:d1:dd | 1ADEBADCB8D4.local | fd00:d:e:f::61 |
| ac:bc:b5:d3:d1:dd | 1ADEBADCB8D4.local | fe80::1887:20b7:1b7:b54 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:30fa:e82e:539c:51b6 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:3550:6ef3:8867:8772 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:496d:ac0d:c2f6:ece5 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:59a6:c01a:b76e:ce0d |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:6838:70c7:833:8ca4 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:90e6:3b22:39f2:aa9f |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:b16a:a413:2b2e:3d14 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | 2404:e80:5346:0:cda:7fd1:d4cf:8f2b |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | fd00:d:e:f:183e:4f13:4044:5684 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | fd00:d:e:f::61 |
| ac:bc:b5:d3:d1:dd | CED845448B3A.local | fe80::1491:5d3e:91a9:266e |
| ac:bc:b5:d3:d1:dd | Eve-Room-2F41.local | fdbb:82f8:256f:0:5327:157a:72a5:413c |
| ac:bc:b5:d3:d1:dd | Eve-Room-2F41.local | fdbb:82f8:256f:0:e1ea:b043:aea8:a393 |
| ac:bc:b5:d3:d1:dd | Eve-Room-2F41.local | fdbb:82f8:256f:0:ec71:ce06:3eb9:7355 |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | 192.168.0.22 |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | 2404:e80:5346:0:cda:7fd1:d4cf:8f2b |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | fd00:d:e:f:183e:4f13:4044:5684 |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | fd00:d:e:f::61 |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | fe80::1491:5d3e:91a9:266e |
| ac:bc:b5:d3:d1:dd | HomePod-2nd-Gen.local | fe80::1887:20b7:1b7:b54 |
| bc:89:c1:d9:60:9c | 05d2b1f6-1ee4-4351-94dd-2eeb43a0bd8e.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 17a7122e-c94c-4153-bbdf-668741339ffd.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 23e543f3-ba96-4560-b1dd-831404a7d11f.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 4449e7f6-f8d6-410d-b205-50962a4be09e.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 4bdd75c2-8d1e-4466-9e52-0130247a8d6a.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 4f619d06-ec21-41ac-9b2d-83f3515774e2.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 503eec67-fadd-4e5e-b167-de552efbbb25.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 503eec67-fadd-4e5e-b167-de552efbbb25.local | 2404:e80:5346:0:1475:e34:f28d:73ad |
| bc:89:c1:d9:60:9c | 503eec67-fadd-4e5e-b167-de552efbbb25.local | fd00:d:e:f:1c6b:3f9c:ab3a:5e30 |
| bc:89:c1:d9:60:9c | 503eec67-fadd-4e5e-b167-de552efbbb25.local | fd00:d:e:f::2 |
| bc:89:c1:d9:60:9c | 503eec67-fadd-4e5e-b167-de552efbbb25.local | fe80::62:bb67:c1e:4a64 |
| bc:89:c1:d9:60:9c | 5fd13a42-4b43-449c-bfb4-4be47fe8d527.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 6ce565c2-9323-4eef-937b-72bb4efb193b.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 7576c1d8-1dfd-4693-b4a2-c616850ee806.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 7c181eff-7130-48ff-900e-a099adfbde53.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | 885d99aa-f041-4547-b440-7bdaf362b1c9.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | Mac-Studio.local | 192.168.0.2 |
| bc:89:c1:d9:60:9c | Mac-Studio.local | 2404:e80:5346:0:1475:e34:f28d:73ad |
| bc:89:c1:d9:60:9c | Mac-Studio.local | fd00:d:e:f:1c6b:3f9c:ab3a:5e30 |
| bc:89:c1:d9:60:9c | Mac-Studio.local | fd00:d:e:f::2 |
| bc:89:c1:d9:60:9c | Mac-Studio.local | fe80::62:bb67:c1e:4a64 |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | 192.168.0.13 |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | 2404:e80:5346:0:1012:e075:8f71:9273 |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | fd00:d:e:f:182e:904d:73e0:e57b |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | fd00:d:e:f::13 |
| c8:80:6d:30:8b:a4 | Mac-mini-Server.local | fe80::cb9:fa07:520e:7ece |
| c8:80:6d:30:8b:a4 | e86847a9-158b-4560-a8fa-949fb081eecb.local | 192.168.0.13 |
| c8:80:6d:30:8b:a4 | e86847a9-158b-4560-a8fa-949fb081eecb.local | 2404:e80:5346:0:1012:e075:8f71:9273 |
| c8:80:6d:30:8b:a4 | e86847a9-158b-4560-a8fa-949fb081eecb.local | fd00:d:e:f:182e:904d:73e0:e57b |
| c8:80:6d:30:8b:a4 | e86847a9-158b-4560-a8fa-949fb081eecb.local | fd00:d:e:f::13 |
| c8:80:6d:30:8b:a4 | e86847a9-158b-4560-a8fa-949fb081eecb.local | fe80::cb9:fa07:520e:7ece |
| d8:3a:dd:dd:7f:61 | 0E_2E_43_4B_F4_16.local | 192.168.2.0 |
| d8:3a:dd:dd:7f:61 | 0E_2E_43_4B_F4_16.local | fd02:d:e:f:: |
| d8:3a:dd:dd:7f:61 | 0E_2E_43_4B_F4_16.local | fe80::ee49:878f:97d4:9850 |
| d8:3a:dd:dd:7f:61 | raspberry-pi.local | 192.168.0.8 |
| d8:3a:dd:dd:7f:61 | raspberry-pi.local | 2404:e80:5346:0:d27a:d211:34e0:c075 |
| d8:3a:dd:dd:7f:61 | raspberry-pi.local | fd00:d:e:f::8 |
| d8:3a:dd:dd:7f:61 | raspberry-pi.local | fd00:d:e:f:d0c0:521b:86a9:e914 |
| ec:b5:fa:bc:52:10 | ecb5fabc5210.local | 192.168.0.50 |
| ec:b5:fa:bc:52:10 | ecb5fabc5210.local | 2404:e80:5346:0:eeb5:faff:febc:5210 |
| ec:b5:fa:bc:52:10 | ecb5fabc5210.local | fd00:d:e:f:eeb5:faff:febc:5210 |
| ec:b5:fa:bc:52:10 | ecb5fabc5210.local | fe80::eeb5:faff:febc:5210 |

## All multicast and broadcast MAC addresses

These are group destinations, not devices: no hostname or hardware vendor applies. IPv6 solicited-node multicast addresses are Neighbor Discovery groups; the last three bytes do not uniquely identify a device. All 113 group destination MACs are listed below.

| MAC | Purpose | Observed IP destination(s) | Capture(s) |
| --- | --- | --- | --- |
| 01:00:5e:00:00:01 | IPv4 multicast | 224.0.0.1 | eth7; wl0.2 |
| 01:00:5e:00:00:16 | IPv4 multicast | 224.0.0.22 | eth7 |
| 01:00:5e:00:00:fb | IPv4 multicast | 224.0.0.251 | eth7; wl0.2 |
| 01:00:5e:00:00:fc | IPv4 multicast | 224.0.0.252 | eth7; wl0.2 |
| 01:00:5e:40:98:8f | IPv4 multicast | 239.192.152.143 | eth7; wl0.2 |
| 01:00:5e:7f:ff:fa | IPv4 multicast | 239.255.255.250 | eth7; wl0.2 |
| 01:80:c2:00:00:00 | STP bridge group | No IP (Layer 2) | eth7; wl0.2 |
| 01:80:c2:00:00:0e | LLDP bridge group | No IP (Layer 2) | eth7; wl0.2 |
| 33:33:00:00:00:01 | IPv6 multicast | ff02::1 | eth7; wl0.2 |
| 33:33:00:00:00:02 | IPv6 multicast | ff02::2 | eth7; wl0.2 |
| 33:33:00:00:00:0c | IPv6 multicast | ff02::c; ff05::c | eth7; wl0.2 |
| 33:33:00:00:00:16 | IPv6 multicast | ff02::16 | eth7 |
| 33:33:00:00:00:fb | IPv6 multicast | ff02::fb | eth7; wl0.2 |
| 33:33:00:01:00:02 | IPv6 multicast | ff02::1:2 | eth7; wl0.2 |
| 33:33:00:01:00:03 | IPv6 multicast | ff02::1:3 | eth7; wl0.2 |
| 33:33:ff:00:00:01 | IPv6 solicited-node multicast | ff02::1:ff00:1 | eth7; wl0.2 |
| 33:33:ff:00:00:02 | IPv6 solicited-node multicast | ff02::1:ff00:2 | eth7; wl0.2 |
| 33:33:ff:00:00:04 | IPv6 solicited-node multicast | ff02::1:ff00:4 | eth7; wl0.2 |
| 33:33:ff:00:00:08 | IPv6 solicited-node multicast | ff02::1:ff00:8 | eth7; wl0.2 |
| 33:33:ff:00:00:13 | IPv6 solicited-node multicast | ff02::1:ff00:13 | eth7; wl0.2 |
| 33:33:ff:00:00:14 | IPv6 solicited-node multicast | ff02::1:ff00:14 | eth7; wl0.2 |
| 33:33:ff:00:00:16 | IPv6 solicited-node multicast | ff02::1:ff00:16 | eth7; wl0.2 |
| 33:33:ff:00:00:43 | IPv6 solicited-node multicast | ff02::1:ff00:43 | eth7; wl0.2 |
| 33:33:ff:00:00:53 | IPv6 solicited-node multicast | ff02::1:ff00:53 | eth7; wl0.2 |
| 33:33:ff:00:00:61 | IPv6 solicited-node multicast | ff02::1:ff00:61 | eth7; wl0.2 |
| 33:33:ff:00:00:68 | IPv6 solicited-node multicast | ff02::1:ff00:68 | eth7; wl0.2 |
| 33:33:ff:00:00:77 | IPv6 solicited-node multicast | ff02::1:ff00:77 | eth7; wl0.2 |
| 33:33:ff:00:00:87 | IPv6 solicited-node multicast | ff02::1:ff00:87 | eth7; wl0.2 |
| 33:33:ff:00:00:a6 | IPv6 solicited-node multicast | ff02::1:ff00:a6 | eth7; wl0.2 |
| 33:33:ff:09:0d:6b | IPv6 solicited-node multicast | ff02::1:ff09:d6b | eth7; wl0.2 |
| 33:33:ff:09:0d:6e | IPv6 solicited-node multicast | ff02::1:ff09:d6e | eth7; wl0.2 |
| 33:33:ff:09:db:b3 | IPv6 solicited-node multicast | ff02::1:ff09:dbb3 | eth7; wl0.2 |
| 33:33:ff:0e:7e:ce | IPv6 solicited-node multicast | ff02::1:ff0e:7ece | eth7; wl0.2 |
| 33:33:ff:0f:f8:b9 | IPv6 solicited-node multicast | ff02::1:ff0f:f8b9 | eth7; wl0.2 |
| 33:33:ff:10:03:a0 | IPv6 solicited-node multicast | ff02::1:ff10:3a0 | eth7; wl0.2 |
| 33:33:ff:12:2e:e1 | IPv6 solicited-node multicast | ff02::1:ff12:2ee1 | eth7; wl0.2 |
| 33:33:ff:13:8b:ed | IPv6 solicited-node multicast | ff02::1:ff13:8bed | eth7; wl0.2 |
| 33:33:ff:14:93:c7 | IPv6 solicited-node multicast | ff02::1:ff14:93c7 | eth7; wl0.2 |
| 33:33:ff:17:2c:11 | IPv6 solicited-node multicast | ff02::1:ff17:2c11 | eth7; wl0.2 |
| 33:33:ff:1d:e6:7f | IPv6 solicited-node multicast | ff02::1:ff1d:e67f | eth7; wl0.2 |
| 33:33:ff:1e:4a:64 | IPv6 solicited-node multicast | ff02::1:ff1e:4a64 | eth7; wl0.2 |
| 33:33:ff:21:c7:c5 | IPv6 solicited-node multicast | ff02::1:ff21:c7c5 | eth7; wl0.2 |
| 33:33:ff:23:1f:03 | IPv6 solicited-node multicast | ff02::1:ff23:1f03 | eth7; wl0.2 |
| 33:33:ff:28:cf:80 | IPv6 solicited-node multicast | ff02::1:ff28:cf80 | eth7; wl0.2 |
| 33:33:ff:29:45:9a | IPv6 solicited-node multicast | ff02::1:ff29:459a | eth7; wl0.2 |
| 33:33:ff:2b:39:60 | IPv6 solicited-node multicast | ff02::1:ff2b:3960 | eth7; wl0.2 |
| 33:33:ff:2f:ac:d7 | IPv6 solicited-node multicast | ff02::1:ff2f:acd7 | eth7; wl0.2 |
| 33:33:ff:30:22:54 | IPv6 solicited-node multicast | ff02::1:ff30:2254 | eth7; wl0.2 |
| 33:33:ff:33:9b:29 | IPv6 solicited-node multicast | ff02::1:ff33:9b29 | eth7; wl0.2 |
| 33:33:ff:3a:5e:30 | IPv6 solicited-node multicast | ff02::1:ff3a:5e30 | eth7; wl0.2 |
| 33:33:ff:3a:d5:ce | IPv6 solicited-node multicast | ff02::1:ff3a:d5ce | eth7; wl0.2 |
| 33:33:ff:3b:fd:32 | IPv6 solicited-node multicast | ff02::1:ff3b:fd32 | eth7; wl0.2 |
| 33:33:ff:44:56:84 | IPv6 solicited-node multicast | ff02::1:ff44:5684 | eth7; wl0.2 |
| 33:33:ff:44:c6:b1 | IPv6 solicited-node multicast | ff02::1:ff44:c6b1 | eth7; wl0.2 |
| 33:33:ff:4a:80:17 | IPv6 solicited-node multicast | ff02::1:ff4a:8017 | eth7; wl0.2 |
| 33:33:ff:4e:a4:5f | IPv6 solicited-node multicast | ff02::1:ff4e:a45f | eth7; wl0.2 |
| 33:33:ff:52:4b:11 | IPv6 solicited-node multicast | ff02::1:ff52:4b11 | eth7; wl0.2 |
| 33:33:ff:5c:e6:36 | IPv6 solicited-node multicast | ff02::1:ff5c:e636 | eth7; wl0.2 |
| 33:33:ff:5f:2a:5a | IPv6 solicited-node multicast | ff02::1:ff5f:2a5a | eth7; wl0.2 |
| 33:33:ff:66:87:5d | IPv6 solicited-node multicast | ff02::1:ff66:875d | eth7; wl0.2 |
| 33:33:ff:6d:70:6a | IPv6 solicited-node multicast | ff02::1:ff6d:706a | eth7 |
| 33:33:ff:70:c4:71 | IPv6 solicited-node multicast | ff02::1:ff70:c471 | eth7; wl0.2 |
| 33:33:ff:71:92:73 | IPv6 solicited-node multicast | ff02::1:ff71:9273 | eth7; wl0.2 |
| 33:33:ff:72:6e:5d | IPv6 solicited-node multicast | ff02::1:ff72:6e5d | eth7; wl0.2 |
| 33:33:ff:72:8c:8c | IPv6 solicited-node multicast | ff02::1:ff72:8c8c | eth7; wl0.2 |
| 33:33:ff:77:9a:4b | IPv6 solicited-node multicast | ff02::1:ff77:9a4b | eth7; wl0.2 |
| 33:33:ff:78:af:12 | IPv6 solicited-node multicast | ff02::1:ff78:af12 | eth7; wl0.2 |
| 33:33:ff:85:ff:ae | IPv6 solicited-node multicast | ff02::1:ff85:ffae | eth7; wl0.2 |
| 33:33:ff:87:2d:e9 | IPv6 solicited-node multicast | ff02::1:ff87:2de9 | eth7; wl0.2 |
| 33:33:ff:8d:73:ad | IPv6 solicited-node multicast | ff02::1:ff8d:73ad | eth7; wl0.2 |
| 33:33:ff:8f:7e:7d | IPv6 solicited-node multicast | ff02::1:ff8f:7e7d | eth7; wl0.2 |
| 33:33:ff:8f:ac:d8 | IPv6 solicited-node multicast | ff02::1:ff8f:acd8 | eth7; wl0.2 |
| 33:33:ff:9a:42:23 | IPv6 solicited-node multicast | ff02::1:ff9a:4223 | eth7; wl0.2 |
| 33:33:ff:9c:51:62 | IPv6 solicited-node multicast | ff02::1:ff9c:5162 | eth7; wl0.2 |
| 33:33:ff:a2:ec:73 | IPv6 solicited-node multicast | ff02::1:ffa2:ec73 | eth7; wl0.2 |
| 33:33:ff:a9:26:6e | IPv6 solicited-node multicast | ff02::1:ffa9:266e | eth7; wl0.2 |
| 33:33:ff:a9:6e:1b | IPv6 solicited-node multicast | ff02::1:ffa9:6e1b | eth7; wl0.2 |
| 33:33:ff:a9:e9:14 | IPv6 solicited-node multicast | ff02::1:ffa9:e914 | eth7; wl0.2 |
| 33:33:ff:ad:b8:86 | IPv6 solicited-node multicast | ff02::1:ffad:b886 | eth7; wl0.2 |
| 33:33:ff:ad:cd:1d | IPv6 solicited-node multicast | ff02::1:ffad:cd1d | eth7; wl0.2 |
| 33:33:ff:af:05:08 | IPv6 solicited-node multicast | ff02::1:ffaf:508 | eth7; wl0.2 |
| 33:33:ff:b4:a5:f7 | IPv6 solicited-node multicast | ff02::1:ffb4:a5f7 | eth7; wl0.2 |
| 33:33:ff:b7:0b:54 | IPv6 solicited-node multicast | ff02::1:ffb7:b54 | eth7; wl0.2 |
| 33:33:ff:b8:0a:e4 | IPv6 solicited-node multicast | ff02::1:ffb8:ae4 | eth7; wl0.2 |
| 33:33:ff:b8:c5:af | IPv6 solicited-node multicast | ff02::1:ffb8:c5af | eth7; wl0.2 |
| 33:33:ff:b9:a2:b4 | IPv6 solicited-node multicast | ff02::1:ffb9:a2b4 | eth7; wl0.2 |
| 33:33:ff:bc:52:10 | IPv6 solicited-node multicast | ff02::1:ffbc:5210 | eth7; wl0.2 |
| 33:33:ff:bc:89:61 | IPv6 solicited-node multicast | ff02::1:ffbc:8961 | eth7; wl0.2 |
| 33:33:ff:be:3d:a4 | IPv6 solicited-node multicast | ff02::1:ffbe:3da4 | eth7; wl0.2 |
| 33:33:ff:c2:69:80 | IPv6 solicited-node multicast | ff02::1:ffc2:6980 | eth7; wl0.2 |
| 33:33:ff:c6:42:f6 | IPv6 solicited-node multicast | ff02::1:ffc6:42f6 | eth7; wl0.2 |
| 33:33:ff:cf:58:f8 | IPv6 solicited-node multicast | ff02::1:ffcf:58f8 | eth7; wl0.2 |
| 33:33:ff:cf:8f:2b | IPv6 solicited-node multicast | ff02::1:ffcf:8f2b | eth7; wl0.2 |
| 33:33:ff:d1:1a:f9 | IPv6 solicited-node multicast | ff02::1:ffd1:1af9 | eth7; wl0.2 |
| 33:33:ff:d2:3d:20 | IPv6 solicited-node multicast | ff02::1:ffd2:3d20 | eth7; wl0.2 |
| 33:33:ff:d2:58:2b | IPv6 solicited-node multicast | ff02::1:ffd2:582b | eth7; wl0.2 |
| 33:33:ff:d4:98:50 | IPv6 solicited-node multicast | ff02::1:ffd4:9850 | eth7; wl0.2 |
| 33:33:ff:d6:ef:81 | IPv6 solicited-node multicast | ff02::1:ffd6:ef81 | eth7; wl0.2 |
| 33:33:ff:d7:68:cb | IPv6 solicited-node multicast | ff02::1:ffd7:68cb | eth7; wl0.2 |
| 33:33:ff:d7:82:3c | IPv6 solicited-node multicast | ff02::1:ffd7:823c | eth7; wl0.2 |
| 33:33:ff:dc:93:d4 | IPv6 solicited-node multicast | ff02::1:ffdc:93d4 | eth7; wl0.2 |
| 33:33:ff:dd:30:96 | IPv6 solicited-node multicast | ff02::1:ffdd:3096 | eth7; wl0.2 |
| 33:33:ff:e0:e5:7b | IPv6 solicited-node multicast | ff02::1:ffe0:e57b | eth7; wl0.2 |
| 33:33:ff:e2:ed:db | IPv6 solicited-node multicast | ff02::1:ffe2:eddb | eth7; wl0.2 |
| 33:33:ff:e7:fd:f0 | IPv6 solicited-node multicast | ff02::1:ffe7:fdf0 | eth7 |
| 33:33:ff:e9:bd:43 | IPv6 solicited-node multicast | ff02::1:ffe9:bd43 | eth7; wl0.2 |
| 33:33:ff:ec:c1:29 | IPv6 solicited-node multicast | ff02::1:ffec:c129 | eth7; wl0.2 |
| 33:33:ff:ee:74:e4 | IPv6 solicited-node multicast | ff02::1:ffee:74e4 | eth7; wl0.2 |
| 33:33:ff:ef:9b:3d | IPv6 solicited-node multicast | ff02::1:ffef:9b3d | eth7; wl0.2 |
| 33:33:ff:f2:14:bb | IPv6 solicited-node multicast | ff02::1:fff2:14bb | eth7; wl0.2 |
| 33:33:ff:f3:8a:d2 | IPv6 solicited-node multicast | ff02::1:fff3:8ad2 | eth7; wl0.2 |
| 33:33:ff:fd:84:b8 | IPv6 solicited-node multicast | ff02::1:fffd:84b8 | eth7; wl0.2 |
| ff:ff:ff:ff:ff:ff | Broadcast | 192.168.0.255; 192.168.114.31; 255.255.255.255 | eth7; wl0.2 |

`00:00:00:00:00:00` also occurs as an ARP target placeholder. It is not an Ethernet endpoint or a resolved host.

## Sources and method

Owner-supplied corrections identify the two Zemismart wall switches and the purposes of the default and VLAN 114 networks. The owner also reports possible Eve Room setup/reset activity during capture; its relationship to the observed identity/address changes is plausible, not confirmed by packet evidence. Device-specific capture evidence comes from the supplied packets: Ethernet/ARP, DHCP/DHCPv6, mDNS/DNS-SD, SSDP/HTTP, LLDP and decoded Tuya discovery. Hardware vendors use Wireshark’s built-in manufacturer registry with longest-prefix matching (including the MMUI /28 assignment). Online sources below corroborate product/protocol interpretation; they do not identify a particular local device.

- [TP-Link P110M official product page](https://www.tp-link.com/us/home-networking/smart-plug/tapo-p110m/v1%20%281-pack%29/) confirms the smart-plug and energy-monitoring function.
- [ARRIS W6U support](https://arris.my.salesforce-sites.com/consumers/articles/Knowledge/W6U-WPS-Wi-Fi-Connection/?fs=RelatedArticle&l=en_US) corroborates the Wi-Fi adapter/extender function.
- [WAVLINK WL-WN586X3 official product page](https://hk.wavlink.com/en_us/product/WL-WN586X3.html) corroborates the model-derived router classification.
- [NETGEAR MS510TX family manual](https://www.downloads.netgear.com/files/GDC/MS510TX/MS510TX_MS510TXPP_UM_EN.pdf) corroborates the switch-family interpretation; the captured string does not identify a specific suffix.
- [TinyTuya UDP discovery implementation](https://github.com/jasonacox/tinytuya/blob/master/tinytuya/core/udp_helper.py) documents the public discovery key and framing used to decode the captured Tuya broadcast.

Capture SHA-256:

- eth7: `e64ae52115b3c30f0137e38687e4afe6bc2e3e613b3a3677d7363cc1365a96df`
- wl0.2: `88be144e5f5727887bfb8e60544624d663fd1aa0ea73fa6fcddafeb79b74e492`
