#!/bin/sh

rm /var/lib/misc/dnsmasq*.leases
service restart_dnsmasq
