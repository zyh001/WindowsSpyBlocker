# Blocking rules

## About

Blocking rules are self-contained in the [`data`]({{ config.repo_url }}/tree/master/data) folder of the repository.
These rules are based on domains or IPs detected during the capture process.

They are separated into **3 distinct categories** that must be chosen carefully if you wish to apply them:

### Spy rules

Spy rules block Windows telemetry and can be found in `data/<type>/spy.txt`.

!!! success "Recommended"

### Update rules

Update rules block Windows Update and can be found in `data/<type>/update.txt`.

### Extra rules

Block third party applications like Skype, Bing, Live, Outlook, NCSI, Microsoft Office, ... and can be found
in `data/<type>/extra.txt`.

!!! danger "ONLY use if you know what you do"
    Be aware that these rules can also block Windows Update and other services.
    
    Therefore, **no support will be provided on them.** 

## Providers

[**Firewall**](firewall.md) and [**Hosts**](hosts.md) blocking rules are the main types. The others are generated
from these as:

* [DNSCrypt](dnscrypt.md): a protocol for securing communications between a client and a DNS resolver.
* [ESET Firewall](eset.md): a proprietary firewall solution.
* [Kaspersky Firewall](kaspersky.md): a proprietary firewall solution.
* [OpenWrt](openwrt.md): an open source project used on embedded devices to route network traffic.
* [P2P](p2p.md): a plaintext IP data format from PeerGuardian.
* [Proxifier](proxifier.md): an advanced proxy client on Windows with a flexible rule system.
* [simplewall](simplewall.md): a simple tool to configure Windows Filtering Platform (WFP).

## How it works?

To capture and interpret network traffic, QEMU virtual machines are used on the server virtualization management
platform [Proxmox VE](https://www.proxmox.com/en/) based on:

* Windows 11 Pro 64bits with automatic updates enabled.
* Windows 10 Pro 64bits with automatic updates enabled.

Traffic dumps are cleaned monthly and compared with the current rules to update hosts and firewall rules.

Following tools are used to capture traffic:

* `qemu -net dump` ; _capture_
* [Wireshark](../app/dev/wireshark.md) ; _capture + logs_
* [Sysmon](../app/dev/sysmon.md) ; _capture + logs_
* [Proxifier](../app/dev/proxifier.md) ; _logs_
