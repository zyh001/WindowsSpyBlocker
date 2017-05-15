<p align="center"><a href="https://github.com/crazy-max/WindowsSpyBlocker" target="_blank"><img width="100"src="https://raw.githubusercontent.com/wiki/crazy-max/WindowsSpyBlocker/img/logo-128.png"></a></p>

<p align="center">
  <a href="https://github.com/crazy-max/WindowsSpyBlocker/releases/latest"><img src="https://img.shields.io/github/release/crazy-max/WindowsSpyBlocker.svg?style=flat-square" alt="GitHub release"></a>
  <a href="https://github.com/crazy-max/WindowsSpyBlocker/releases/latest"><img src="https://img.shields.io/github/downloads/crazy-max/WindowsSpyBlocker/total.svg?style=flat-square" alt="Total downloads"></a>
  <a href="https://ci.appveyor.com/project/crazy-max/WindowsSpyBlocker"><img src="https://img.shields.io/appveyor/ci/crazy-max/WindowsSpyBlocker.svg?style=flat-square" alt="AppVeyor"></a>
  <a href="https://goreportcard.com/report/github.com/crazy-max/WindowsSpyBlocker"><img src="https://goreportcard.com/badge/github.com/crazy-max/WindowsSpyBlocker?style=flat-square" alt="Go Report"></a>
  <a href="https://www.codacy.com/app/crazy-max/WindowsSpyBlocker"><img src="https://img.shields.io/codacy/grade/1e2eae1a40754d88b7956cf9bd30241b.svg?style=flat-square" alt="Code Quality"></a>
  <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CXF2HBWCMSZVL"><img src="https://img.shields.io/badge/donate-paypal-blue.svg?style=flat-square" alt="Donate Paypal"></a>
  <a href="https://flattr.com/submit/auto?user_id=crazymax&url=https://github.com/crazy-max/WindowsSpyBlocker"><img src="https://img.shields.io/badge/flattr-this-green.svg?style=flat-square" alt="Flattr this!"></a>
</p>

## About

**WindowsSpyBlocker** is a set of rules to block Windows spy / telemetry based on multiple tools to capture traffic located in the `data` folder. [An application is also available](https://github.com/crazy-max/WindowsSpyBlocker/releases/latest) to perform several extra operations.<br />
It is open for everyone and if you want to contribute or need help, take a look at the [Wiki](../../wiki).

## How ?

I use QEMU virtual machines on the server virtualization management platform [Proxmox VE](https://www.proxmox.com/en/) based on :

* Windows 10 Pro 64bits with automatic updates enabled.
* Windows 8.1 Pro 64bits with automatic updates enabled.
* Windows 7 SP1 Pro 64bits with automatic updates enabled.

I clean traffic dumps every day and compare results with the current rules to add / remove some hosts or firewall rules.

Tools used to capture traffic :
* **qemu -net dump** : capture
* **[Wireshark](../../wiki/devWireshark)** : capture + logs
* **[Sysmon](../../wiki/devSysmon)** : capture + logs
* **[Proxifier](../../wiki/devProxifier)** : logs

All traffic events are available in the [logs](#logs) folder.<br />
You can read the [Telemetry](../../wiki/Telemetry) page if you want more info about data collection.

## The app

WindowsSpyBlocker is delivered as a single executable available in the [latest release page](https://github.com/crazy-max/WindowsSpyBlocker/releases/latest) that embeds the data located in the `data` directory of the repository.
It allows to apply the rules to the Windows firewall, to modify the NCSI and also to help contribute to the project!

![](../../wiki/img/wsb-20170515.png)
> Main window of WindowsSpyBlocker application

Configuration files `app.conf` and `libs.conf` are generated at first launch :

![](../../wiki/img/wsbRootFolder-20170515.png)

For more information, read the instructions in the [Wiki](../../wiki).

## Data

`data` is the master folder of this project. It contains the blocking rules based on domain names or IPs addresses detected during the capture process.
* `data/<type>/winX/spy.txt` : Block Windows Spy / Telemetry
* `data/<type>/winX/update.txt` : Block Windows Update
* `data/<type>/winX/extra.txt` : Block third party applications

### Hosts

Copy / paste the content of the files in `data/hosts` in your Windows hosts file located in `C:\Windows\System32\drivers\etc\hosts`.<br />
For more information, read the instructions in [Hosts Wiki page](../../wiki/Hosts).

### Firewall

Some queries use IP addresses but you can stop them with your Firewall.<br />
All relative information about these IP addresses are listed in the CSV files `firewall-` in the [logs folder](logs).<br />
To add / remove firewall rules or test IPs, read the instructions on the [Firewall Wiki page](../../wiki/Firewall).

### NCSI (Network Connectivity Status Indicator)

Windows check a Microsoft site for connectivity, using the Network Connectivity Status Indicator site.<br />
NCSI performs a DNS lookup on `www.msftncsi.com` and sends a DNS lookup request for `dns.msftncsi.com`.<br />
You can block this probe by adding the content of the `data/<type>/winX/extra.txt` hosts file.<br />

But you will have a ["No Internet access" warning in your system tray](../../wiki/FAQ#no-internet-access-on-my-network-card).<br />
To solve this problem you can use the alternative WindowsSpyBlocker NCSI.<br />
For more information, read the instructions on the [NCSI Wiki page](../../wiki/NCSI).

### DNSCrypt

[DNSCrypt](https://dnscrypt.org/) is a protocol for securing communications between a client and a DNS resolver. With this tool you can blacklist some domains with the plugin [libdcplugin_example_ldns_blocking](https://github.com/jedisct1/dnscrypt-proxy#plugins) and add domains with leading and trailing wildcards.<br />
To install DNSCrypt on Windows, read the [README-WINDOWS](https://github.com/jedisct1/dnscrypt-proxy/blob/master/README-WINDOWS.markdown) on the official GitHub repository.<br />
Copy the content of the dnscrypt files in the repository in a file called for example `C:\blacklisted-domains.txt` and enter this command :

```
dnscrypt-proxy -R <name> --plugin=libdcplugin_example_ldns_blocking.dll,--domains=C:\blacklisted-domains.txt
```

Replace `<name>` with a [public DNS resolvers supporting DNSCrypt](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv) you want to use. Note its name, in the first column (for example: `dnscrypt.org-fr`).

### Proxifier

Some hosts are not blocked and required a top level application.<br />
For example you can use [Proxifier](https://www.proxifier.com/) software to block Microsoft spy.

For more information, read the instructions on the [Proxifier Wiki page](../../wiki/devProxifier).


### OpenWrt

DNS/IP block rules using dnsmasq / iptables are available in `data/openwrt` folder.<br />
These rules are focused on latest OpenWrt release (Chaos Calmer 15.05.1).<br />

Requires package "iptables-mod-nat-extra" for port 53 (DNS) redirect rule from dnsmasq.conf.<br />
dnsmasq.conf is bypassed if you use DNSCrypt on client machine (recommended) so use hosts before DNSCrypt exit point.<br />

DNSCrypt is also available in OpenWrt repo, but may be slow and CPU hungry on average routers, stay with the PC client as recommended.

## Logs

Logs of tools used to capture traffic and resolution of firewall rules in CSV format available in the [logs folder](logs).
* `*-hosts-count.csv` : number of events per host
* `*-unique.csv` : first trigger of an event per host / process / destination port

## Projects using WindowsSpyBlocker

* [pi-hole](https://pi-hole.net/) : A black hole for Internet advertisements (designed for Raspberry Pi).
* [StopAd](http://stopad.generate.club/) : Service for MikroTik routers made to block "advertising" and more.
* [OpenWrt adblock package](https://github.com/openwrt/packages/tree/master/net/adblock/files) : DNS based ad/abuse domain blocking
* [Unified hosts file](https://github.com/StevenBlack/hosts) : Extending and consolidating hosts files from a variety of sources.
* [FreeContributor](https://tbds.github.io/FreeContributor/) : Simple DNS Ad Blocker.

## How can i help ?

We welcome all kinds of contributions :raised_hands:!<br />
The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:<br />
Any funds donated will be used to help further development on this project! :gift_heart:

<p>
  <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CXF2HBWCMSZVL">
    <img src="../../wiki/img/paypal.png" alt="Donate Paypal">
  </a>
  <a href="https://flattr.com/submit/auto?user_id=crazymax&url=https://github.com/crazy-max/WindowsSpyBlocker">
    <img src="../../wiki/img/flattr.png" alt="Flattr this!">
  </a>
</p>

## License

MIT. See `LICENSE` for more details.<br />
Icon credit to [Icons8](https://icons8.com/).
