# Changelog

## 4.2.1 (2017/05/27)

* Windows Store cannot download apps (Issue #15)

## 4.2.0 (2017/05/23)

* Move Firewall and NCSI to the Telemetry parent menu
* Simplify the README

## 4.1.1 (2017/05/21)

* New hosts for Windows 10 extra, spy and update
* New IP for Windows 10 update
* New IPs for Windows 10 spy
* Typo in Windows 10 spy
* Add IP range for Windows 10 spy (65.55.252)
* New sub IP for Windows 10 extra (40.77.224)
* Typo in Windows 10 extra
* New hosts for Windows 8.1 spy and update
* New sub IP and IP for Windows 8.1 update (191.234.72)
* New sub IPs and IP for Windows 8.1 spy (13.79.239, 13.81.59)
* New hosts for Windows 7 spy and update
* New sub IPs and IP for Windows 7 spy (13.79.239, 51.141.32)
* Handle panic (Issue #58)
* Add menu to merge data (Issue #57)
* Missing print for firewall tests (Issue #56)
* Perform upgrade operations on new release (Issue #55)
* Add new release notification on startup (Issue #54)
* Update app.conf if keys are missing on update (Issue #53)
* Provide libs infos in the code (Issue #52)
* Null pointer on NCSI test (Issue #50)
* Add a menu on Wireshark to capture traffic (Issue #48)
* Separate IPs and domains for Proxifier rules
* Remove NCSI reg files
* Enhanced menu
* Upgrade Wireshark lib
* Duplicated diffs
* Code review

## 4.0.0 (2017/05/15)

* Unified console app made with Go (Issue #38)
* Add Glide dependency manager for Go
* Add Codacy review
* Add AppVeyor CI integration
* Add Go Report badge
* Standard code organization
* Move 131.253.61.0-131.253.61.255 to extra for Windows 8.1 (Issue #39)
* Move *.vo.msecnd.net to extra rules (Issue #37)

## 3.7.5 (2017/04/15)

* New hosts for Windows 10 spy and update
* New IP for Windows 10 update
* Add IP range for Windows 10 update (65.55.163) 
* New IPs for Windows 10 spy
* New sub IPs for Windows 10 spy (51.141.32, 52.178.178, 52.178.193, 52.178.223, 52.187.60)
* New sub IP for Windows 10 extra (13.107.21)
* New hosts for Windows 8.1 extra, spy and update
* Add IP range for Windows 8.1 update (65.55.163)
* New sub IPs for Windows 8.1 spy (51.141.32, 52.178.178, 52.178.193, 52.178.223, 52.187.60, 64.233.164, 64.233.166)
* New hosts for Windows 7 spy and update
* New sub IPs for Windows 7 spy (40.118.106, 52.178.178, 52.178.193, 52.178.223, 52.187.60)
* Move crl.microsoft.com to extra rules for Windows 7 (Issue #19)

## 3.7.4 (2017/03/07)

* New hosts for Windows 10 spy
* Add IPs range for Windows 10 spy (131.253.14, 157.55.109)
* New sub IP for Windows 10 update (131.253.33)
* New hosts for Windows 8.1 extra and update
* New sub IP for Windows 8.1 extra (40.118.106)
* New IP for Windows 8.1 update
* New host for Windows 7 update
* Misplaced IPs blocking Windows update bug (Issue #33)
* Skype problem (Issue #32)
* Move 134.170.185.* to extra rules (Issue #31)
* Move 48.118.103 and 65.52.108 to extra rules for Windows 10
* Missing IP in OpenWRT extra rules (Windows 8.1 and 10)

## 3.7.3 (2017/01/23)

* Move answers.microsoft.com to extra rules
* choice.microsoft.com was not completely moved to extra rules

## 3.7.2 (2017/01/22)

* New hosts for Windows 10 spy and update
* Add IP range for Windows 10 spy (134.170.111)
* New sub IP for Windows 10 spy (52.164.240)
* New IPs for Windows 10 spy
* New hosts for Windows 8.1 update
* Move officeclient.microsoft.com to extra rules (Issue #29)
* Move m.hotmail.com to extra rules (Issue #28)

## 3.7.1 (2016/12/19)

* New hosts for Windows 10 spy
* New sub IPs for Windows 10 spy (40.113.10, 40.115.1, 52.178.151, 65.52.26, 104.46.38, 134.170.120) 
* New sub IP for Windows 8.1 update (191.232.80)

## 3.7.0 (2016/11/28)

* New hosts for Windows 10 spy and update
* Add IPs range for Windows 10 spy (40.77.229, 134.170.106)
* New sub IPs for Windows 10 spy (23.97.61, 23.99.121, 40.76.1, 40.117.144, 65.52.219, 104.210.212, 134.170.111, 134.170.120, 157.55.109, 191.237.218, 207.46.194)
* Move spy IP rule to update for Windows 10 (157.55.133.204)
* New hosts for Windows 7 update
* New sub IPs for Windows 7 spy (52.164.241, 52.178.147)
* Fix undefined index
* Fix tmp file creation
* Downloads from Xbox Store broken (Issue #24)
* OpenWRT dnsmasq.conf alternative method (Issue #20)

## 3.6.0 (2016/11/06)

* New hosts for Windows 10 spy
* Add IPs range for Windows 10 update (65.55.138)
* Add IPs range for Windows 10 spy (40.77.226, 64.4.54, 65.52.100)
* New sub IPs for Windows 10 spy (13.76.218, 40.77.229, 52.178.147, 137.170.51, 134.170.115)
* New hosts for Windows 8.1 update
* Add IPs range for Windows 8.1 update (65.55.138, 134.170.51)
* New sub IPs for Windows 8.1 update (134.170.115)
* New sub IPs for Windows 8.1 spy (40.77.226, 52.164.240, 52.164.241, 52.178.147, 52.178.151)
* New sub IPs for Windows 7 spy (40.77.226, 52.164.240, 52.178.151)
* Update Proxifier script exceptions
* Windows 10 Store Blocked (Issue #22)

## 3.5.0 (2016/09/18)

* New hosts and firewall rules
* 2 Spy entries are maybe incorrect (Issue #19)

## 3.4.4 (2016/08/02)

* New hosts and firewall rules

## 3.4.3 (2016/07/24)

* New hosts and firewall rules

## 3.4.2 (2016/07/12)

* New hosts and firewall rules

## 3.4.1 (2016/07/03)

* New hosts and firewall rules

## 3.4.0 (2016/06/24)

* New hosts and firewall rules
* Scripts more verbose
* Skip diff if file not exist

## 3.3.1 (2016/06/18)

* New hosts and firewall rules
* Fix login problem on Windows Store (Issue #15)

## 3.3.0 (2016/06/12)

* New hosts and firewall rules
* Resolve domains history via ThreatCrowd
* Manage CDNs
* Diffs reports in CSV format
* Add additional whois and resolutions API

## 3.2.0 (2016/06/08)

* Add third digit to release version for rules updates only
* New hosts and firewall rules
* Better diffs order
* Update and separate OpenWrt dnsmasq / iptables files

## 3.1 (2016/06/07)

* Add Windows 7 and Windows 8.1 hosts and firewall rules (Issue #1)
* Add Wireshark script to extract log and generate CSV (Issue #6)
* Bug spy rule blocking Windows update (Issue #14)
* Add diff script to compare current firewall rules / hosts with generated CSVs
* New hosts and firewall rules

## 3.0 (2016/06/03)

* Add Sysmon, Proxifier, Wireshark capture method in the [Wiki](../../wiki) (Issue #11)
* Enhancement for firewall script (Issue #2)
* Separate rules and scripts in distinct folders
* New hosts and firewall rules
* Add capture logs in CSV files
* Add Sysmon script (install / uninstall / extract event log)
* Add Proxifier script (extract log)

## 2.7 (2016/05/27)

* Add NCSI alternative probe (Issue #9)
* Allow Network Connectivity Status Indicator (Issue #8)
* Windows Update was blocked unintentional. (Issue #7)
* New firewall rules
* Add Windows Update firewall rules
* New hosts
* Add IPs to Proxifier rules (copy from firewall rules)
* Remove reverse DNS lookup hosts
* Update [FAQ](../../wiki/FAQ)

## 2.6 (2016/05/22)

* New firewall rules
* New extra host
* Add check on IP range
* Rename hosts files

## 2.5 (2016/05/16)

* Add instructions to use blacklist domains with DNSCrypt (Issue #5)
* Add DNSCrypt blacklisted domains files
* Rename firewall and proxifier files according to operating system
* New firewall rules
* Move rules to extra for Proxifier and DNSCrypt

## 2.4 (2016/05/16)

* New firewall rules
* New extra hosts
* Move `204.79.197.200` to extra firewall rules (Bing)
* Add relative information about firewall IP addresses in `firewallTestIPs.csv` file

## 2.3 (2016/05/15)

* New firewall rules
* New hosts
* Add extra firewall rules in a separate file
* Add test IPs menu in firewall script

## 2.2 (2016/05/15)

* New firewall rules
* Add logo (credit to DWS)

## 2.1 (2016/05/14)

* New firewall rules since Microsoft Patch Tuesday May 2016

## 2.0 (2016/05/14)

* Update hosts Windows Extra
* Add Firewall rules

## 1.5 (2016/03/29)

* New hosts since KB3140768
* Add third party applications blocking file

## 1.4 (2016/03/06)

* New hosts since KB3135173
* Add Windows Update block rules

## 1.3 (2016/03/04)

* Initial version
