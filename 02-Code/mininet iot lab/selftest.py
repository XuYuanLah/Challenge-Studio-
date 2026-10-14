#!/usr/bin/env python3
"""Quick connectivity assertions for each mode. Development aid."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mininet.log import setLogLevel
setLogLevel('warning')
import iot_lab
from lab import config as C

mode = sys.argv[1] if len(sys.argv) > 1 else 'flat'
dp = sys.argv[2] if len(sys.argv) > 2 else 'user'

net, hosts, r1, cloud = iot_lab.build(mode, dp, False)
iot_lab.start_services(hosts, r1, cloud, mode, speed=60.0,
                       logdir=f'/tmp/selftest-{mode}', quiet=True)
time.sleep(4)

def ping(src, dst_ip, n=1):
    out = hosts[src].cmd(f'ping -c{n} -W1 {dst_ip} 2>&1')
    return '1 received' in out or f'{n} received' in out

def tcp(src, dst_ip, port):
    out = hosts[src].cmd(
        f'timeout 3 python3 -c "'
        f'import socket,sys;s=socket.socket();s.settimeout(2);'
        f'sys.exit(0 if s.connect_ex((\'{dst_ip}\',{port}))==0 else 1)"'
        f'; echo rc=$?')
    return 'rc=0' in out

nas = C.BY_NAME['nas'].ip(mode)
dns = C.BY_NAME['dns'].ip(mode)
plug = C.BY_NAME['iotplug'].ip(mode)

print(f'=== mode={mode} ===')
cam = 'iotcam'
gw = C.BY_NAME[cam].gateway(mode)
print(f'{cam} -> gateway             : {ping(cam, gw)}')
print(f'{cam} -> nas (main LAN ping) : {ping(cam, nas)}')
print(f'{cam} -> cloud (internet)    : {ping(cam, C.CLOUD_IP)}')
print(f'{cam} -> iotplug (same seg)  : {ping(cam, plug)}')
print(f'nas -> {cam} (main->IoT)     : {ping("nas", C.BY_NAME[cam].ip(mode))}')
print(f'{cam} -> nas:445 TCP         : {tcp(cam, nas, 445)}')
print(f'{cam} -> dns:53 TCP          : {tcp(cam, dns, 53)}')
print(f'{cam} -> router:22 TCP       : {tcp(cam, gw, 22)}')

iot_lab.stop_all(net, hosts, r1, cloud)
net.stop()
