[![GitHub release](https://img.shields.io/github/release/crazy-max/WindowsSpyBlocker.svg?style=flat-square)](https://github.com/crazy-max/WindowsSpyBlocker/releases)
[![Donate Paypal](https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square)](https://www.paypal.me/crazyws)

# Windows Spy Blocker

![](../../wiki/img/logo-20160521.png)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [About](#about)
- [How ?](#how-)
- [Usage](#usage)
  - [Data](#data)
    - [Hosts](#hosts)
    - [Firewall](#firewall)
    - [NCSI (Network Connectivity Status Indicator)](#ncsi-network-connectivity-status-indicator)
    - [DNSCrypt](#dnscrypt)
    - [Proxifier](#proxifier)
    - [OpenWrt](#openwrt)
  - [Logs](#logs)
  - [Scripts](#scripts)
- [Projects using WindowsSpyBlocker](#projects-using-windowsspyblocker)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## About

**WindowsSpyBlocker** is a set of rules to block Windows spy / telemetry based on multiple tools to [capture traffic](../../wiki/Capture%20traffic). It is open for everyone and if you want to contribute, take a look at the [Wiki](../../wiki).<br />
To be notified of new releases you can subscribe to this [Atom feed](https://github.com/crazy-max/WindowsSpyBlocker/releases.atom).

## How ?

I use QEMU virtual machines on the server virtualization management platform [Proxmox VE](https://www.proxmox.com/en/) based on :

* Windows 10 Pro 64bits with automatic updates enabled.
* Windows 8.1 Pro 64bits with automatic updates enabled.
* Windows 7 SP1 Pro 64bits with automatic updates enabled.

I clean traffic dumps every day and compare results with the current rules to add / remove some hosts or firewall rules.

Tools used to capture traffic :
* **qemu -net dump** : capture
* **[Wireshark](../../wiki/captureWireshark)** : capture + logs
* **[Sysmon](../../wiki/captureSysmon)** : capture + logs
* **[Proxifier](../../wiki/captureProxifier)** : logs

All traffic events are available in the [logs](#logs) folder.

## Usage

### Data

`data` is the master folder of this project. It contains the blocking rules based on domain names or IPs addresses detected during the capture process.
* `data/<type>/winX/spy.txt` : Block Windows Spy / Telemetry
* `data/<type>/winX/update.txt` : Block Windows Update
* `data/<type>/winX/extra.txt` : Block third party applications

#### Hosts

Copy / paste the content of the files in `data/hosts` in your Windows hosts file located in `C:\Windows\System32\drivers\etc\hosts`.<br />

You can use the [HostsMan](http://www.abelhadigital.com/hostsman) freeware to keep update your hosts file.<br />
I have created a git hook to publish the hosts files to my personal website :

##### Windows 7
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/spy.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/spy.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/update.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/update.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/extra.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win7/extra.txt)

##### Windows 8.1
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/spy.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/spy.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/update.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/update.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/extra.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win81/extra.txt)

##### Windows 10
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/spy.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/spy.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/update.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/update.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/extra.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/win10/extra.txt)

#### Firewall

Some queries use IP addresses but you can stop them with your Firewall.<br />
All relative information about these IP addresses are listed in the CSV files `firewall-` in the [logs folder](logs).<br />
To add / remove firewall rules or test IPs, read the instructions in [scripts/firewall folder](scripts/firewall).

#### NCSI (Network Connectivity Status Indicator)

Windows check a Microsoft site for connectivity, using the Network Connectivity Status Indicator site.<br />
NCSI performs a DNS lookup on `www.msftncsi.com` and sends a DNS lookup request for `dns.msftncsi.com`.<br />
You can block this probe by adding the content of the `data/<type>/winX/extra.txt` hosts file.<br />

But you will have a ["No Internet access" warning in your system tray](../../wiki/FAQ#no-internet-access-on-my-network-card).<br />
To solve this problem you can use the alternative WindowsSpyBlocker NCSI. Read the instructions in [scripts/ncsi folder](scripts/ncsi).

#### DNSCrypt

[DNSCrypt](https://dnscrypt.org/) is a protocol for securing communications between a client and a DNS resolver. With this tool you can blacklist some domains with the plugin [libdcplugin_example_ldns_blocking](https://github.com/jedisct1/dnscrypt-proxy#plugins) and add domains with leading and trailing wildcards.<br />
To install DNSCrypt on Windows, read the [README-WINDOWS](https://github.com/jedisct1/dnscrypt-proxy/blob/master/README-WINDOWS.markdown) on the official GitHub repository.<br />
Copy the content of the dnscrypt files in the repository in a file called for example `C:\blacklisted-domains.txt` and enter this command :

```
dnscrypt-proxy -R <name> --plugin=libdcplugin_example_ldns_blocking.dll,--domains=C:\blacklisted-domains.txt
```

Replace `<name>` with a [public DNS resolvers supporting DNSCrypt](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv) you want to use. Note its name, in the first column (for example: `dnscrypt.org-fr`).

#### Proxifier

Some hosts are not blocked and required a top level application.<br />
For example you can use [Proxifier](https://www.proxifier.com/) software to block Microsoft spy.<br />
Copy the content of the proxifier files in `data/proxifier` in a blocked rule :

![](../../wiki/img/proxifierRules-20160516.png)

#### OpenWrt

DNS/IP block rules using dnsmasq / iptables are available in `data/openwrt` folder.<br />
These rules are focused on latest OpenWrt release (Chaos Calmer 15.05.1).<br />

Requires package "iptables-mod-nat-extra" for port 53 (DNS) redirect rule from dnsmasq.conf.<br />
dnsmasq.conf is bypassed if you use DNSCrypt on client machine (recommended) so use hosts before DNSCrypt exit point.<br />

DNSCrypt is also available in OpenWrt repo, but may be slow and CPU hungry on average routers, stay with the PC client as recommended.

### Logs

Logs of tools used to capture traffic and resolution of firewall rules in CSV format available in the [logs folder](logs).
* `*-all.csv` : all events
* `*-hosts-count.csv` : number of events per host
* `*-unique.csv` : first trigger of an event per host / process / destination port

### Scripts

Several scripts are used to ease implementation of rules and contribution. To use these scripts you have to download and install the [Visual C++ Redistributable for Visual Studio 2012](https://www.microsoft.com/en-us/download/details.aspx?id=30679) (vcredist_x86.exe).
* `diff.bat` : Generate a diff log based on CSV logs and data for Sysmon, Proxifier and Wireshark.
* `firewall.bat` : Add / remove rules and resolve IPs adresses
* `ncsi.bat` : Apply an alternate NCSI and test your internet connection the Microsoft way. [More info...](../../wiki/FAQ#what-is-ncsi-)
* `proxifier.bat` : Extract events from log and generate CSV files. [More info...](../../wiki/captureProxifier)
* `sysmon.bat` : Install / uninstall Sysmon and extract events log then generate CSV files. [More info...](../../wiki/captureSysmon)
* `wireshark.bat` : Extract events log then generate CSV files based on IPv4 hosts. [More info...](../../wiki/captureWireshark)

## Projects using WindowsSpyBlocker

* [pi-hole](https://pi-hole.net/) : A black hole for Internet advertisements (designed for Raspberry Pi).
* [StopAd](http://stopad.generate.club/) : Service for MikroTik routers made to block "advertising" and more.
* [OpenWrt adblock package](https://github.com/openwrt/packages/tree/master/net/adblock/files) : DNS based ad/abuse domain blocking

## License

MIT. See `LICENSE` for more details.
