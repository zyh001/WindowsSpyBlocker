# OpenWrt

!!! info
    OpenWrt blocking rules available at [{{ config.repo_url }}tree/master/data/openwrt]({{ config.repo_url }}tree/master/data/openwrt)

DNS/IP block rules using dnsmasq/iptables are available in `data/openwrt` folder. These rules are currently compatible with
OpenWrt version Chaos Calmer 15.05.1.

Requires package `iptables-mod-nat-extra` for port 53 (DNS) redirect rule from dnsmasq.conf. `dnsmasq.conf` is
bypassed if you use DNSCrypt on client machine (recommended) so use hosts before DNSCrypt exit point.

DNSCrypt is also available in OpenWrt repo, but may be slow and CPU hungry on average routers, stay with the PC
client as recommended.
