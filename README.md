# Windows Spy Blocker [![Donate Paypal](https://img.shields.io/badge/donate-paypal-blue.svg)](https://www.paypal.me/crazyws)

Rules to block Windows spy / telemetry.

![](../../wiki/img/logo-20160521.png)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [How ?](#how-)
- [Usage](#usage)
  - [Hosts](#hosts)
  - [Firewall](#firewall)
  - [NCSI (Network Connectivity Status Indicator)](#ncsi-network-connectivity-status-indicator)
  - [DNSCrypt](#dnscrypt)
  - [Proxifier](#proxifier)
- [Projects using WindowsSpyBlocker](#projects-using-windowsspyblocker)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## How ?

I use a QEMU virtual machine on the server virtualization management platform [Proxmox VE](https://www.proxmox.com/en/) based on Windows 10 Pro 64bits with automatic updates enabled.<br />
I clean traffic dumps every day and compare results with the current rules to add / remove some hosts or firewall rules (need to automate the process...).

Tools used to capture traffic :
* qemu -net dump
* Wireshark

## Usage

### Hosts

* `windowsX_spy.txt` : Block Windows Spy / Telemetry
* `windowsX_update.txt` : Block Windows Update
* `windowsX_extra.txt` : Block third party applications

Copy / paste the content of the above files in your Windows hosts file located in `C:\Windows\System32\drivers\etc\hosts`.<br />

You can use the [HostsMan](http://www.abelhadigital.com/hostsman) freeware to keep update your hosts file.<br />
I have created a git hook to publish the hosts files to my personal website :
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_spy.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_spy.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_update.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_update.txt)
* [http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_extra.txt](http://www.crazyws.fr/WindowsSpyBlocker/hosts/windows10_extra.txt)

### Firewall

Some queries use IP addresses but you can stop them with your Firewall.<br />
All relative information about these IP addresses are listed in the CSV file [firewallTestIPs.csv](https://github.com/crazy-max/WindowsSpyBlocker/blob/master/firewall/firewallTestIPs.csv).<br />
[Download](https://github.com/crazy-max/WindowsSpyBlocker/archive/master.zip) or clone the repository, execute `firewall\firewallBlockWindowsSpy.bat` and choose an option :<br />

![](../../wiki/img/firewallMenu-20160516.png)

IPs are added in the Windows Firewall as outbound rules :<br />

![](../../wiki/img/firewallRules-20160516.png)

### NCSI (Network Connectivity Status Indicator)

Windows check a Microsoft site for connectivity, using the Network Connectivity Status Indicator site.<br />
NCSI performs a DNS lookup on `www.msftncsi.com` and sends a DNS lookup request for `dns.msftncsi.com`.<br />
You can block this probe by adding the content of the `windowsX_extra.txt` hosts file.<br />

But you will have ["No Internet access" warning in your system tray](../../wiki/FAQ#no-internet-access-on-my-network-card).<br />
To solve this problem you can use the alternative WindowsSpyBlocker NCSI by executing `ncsi\ncsi.bat` :<br />

![](../../wiki/img/ncsiMenu-20160527.png)

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
For example you can use [Proxifier](https://www.proxifier.com/) software to block Microsoft spy.<br />
Copy the content of the proxifier files in the repository in a blocked rule :

![](../../wiki/img/proxifierRules-20160516.png)

## Projects using WindowsSpyBlocker

* [pi-hole](https://pi-hole.net/) : A black hole for Internet advertisements (designed for Raspberry Pi).
* [StopAd](http://stopad.generate.club/) : Service for MikroTik routers made to block "advertising" and more.

## License

MIT. See `LICENSE` for more details.
