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

**WindowsSpyBlocker** :shield: is an application written in [Go](https://golang.org/) and delivered as a [single executable](https://github.com/crazy-max/WindowsSpyBlocker/releases/latest) to block spying and tracking on Windows systems :no_entry:. The initial approach of this application is to capture and analyze network traffic :vertical_traffic_light: based on a set of tools. It is open for everyone and if you want to contribute or need help, take a look at the [Wiki](../../wiki) :open_book:.

![](../../wiki/img/wsb-20170523.png)
> Main window of WindowsSpyBlocker

Configuration file `app.conf` is generated at first launch :

![](../../wiki/img/wsbRootFolder-20170517.png)

For more info, take a look at [Wiki](../../wiki).

## Telemetry and data collection

To capture and analyze network traffic for the telemetry option, QEMU virtual machines are used on the server virtualization management platform [Proxmox VE](https://www.proxmox.com/en/) based on :

* Windows 10 Pro 64bits with automatic updates enabled.
* Windows 8.1 Pro 64bits with automatic updates enabled.
* Windows 7 SP1 Pro 64bits with automatic updates enabled.

Traffic dumps are clean every day and compared with the current rules to add / remove some hosts or firewall rules.

Tools used to capture traffic :

* `qemu -net dump` : capture
* [Wireshark](../../wiki/appDevWireshark) : capture + logs
* [Sysmon](../../wiki/appDevSysmon) : capture + logs
* [Proxifier](../../wiki/devProxifier) : logs

All traffic events are available in the `logs` folder :

* `*-hosts-count.csv` : number of events per host
* `*-unique.csv` : first trigger of an event per host / process / destination port

The `data` folder contains the blocking rules based on domains or IPs detected during the capture process :

* `data/<type>/winX/spy.txt` : Block Windows Spy / Telemetry
* `data/<type>/winX/update.txt` : Block Windows Update
* `data/<type>/winX/extra.txt` : Block third party applications

[Firewall](../../wiki/dataFirewall) and [Hosts](../../wiki/dataHosts) data are the main types. The others are generated from these as :

* [DNSCrypt](../../wiki/dataDNSCrypt) : a protocol for securing communications between a client and a DNS resolver.
* [OpenWrt](../../wiki/dataOpenWrt) : an open source project used on embedded devices to route network traffic.
* [P2P](../../wiki/dataP2P) : a plaintext IP data format from PeerGuardian.
* [Proxifier](../../wiki/dataProxifier) : an advanced proxy client on Windows with a flexible rule system.
* [Simplewall](../../wiki/dataSimplewall) : a simple tool to configure Windows Filtering Platform (WFP).

And about data collection, you can read the [Telemetry collection](../../wiki/miscTelemetry) page for more info.

## Projects using WindowsSpyBlocker

* [pi-hole](https://pi-hole.net/) : A black hole for Internet advertisements (designed for Raspberry Pi).
* [StopAd](http://stopad.generate.club/) : Service for MikroTik routers made to block "advertising" and more.
* [OpenWrt adblock package](https://github.com/openwrt/packages/tree/master/net/adblock/files) : DNS based ad/abuse domain blocking
* [Unified hosts file](https://github.com/StevenBlack/hosts) : Extending and consolidating hosts files from a variety of sources.
* [FreeContributor](https://tbds.github.io/FreeContributor/) : Simple DNS Ad Blocker.
* [WPD](https://getwpd.com/) : Customize Group Policy, Services and Tasks, responsible for data collection and sending, as you like.
* [simplewall](https://github.com/henrypp/simplewall) : Simple tool to configure Windows Filtering Platform (WFP)

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
