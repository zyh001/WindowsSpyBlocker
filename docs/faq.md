# FAQ

## No Internet access on my network card

![](assets/faq/no-internet-access.png)

Windows check a Microsoft site for connectivity, using the Network Connectivity Status Indicator site.

* NCSI performs a DNS lookup on `www.msftconnecttest.com`, then requests `http://www.msftconnecttest.com/connecttest.txt`.
This file is a plain-text file and contains only the text `Microsoft Connect Test`.
* NCSI sends a DNS lookup request for `dns.msftncsi.com`. This DNS address should resolve to `131.107.255.255`.
If the address does not match, then it's assumed that the internet connection is not functioning correctly.

If you want to implement your own NCSI, [check this blog post](http://blog.superuser.com/2011/05/16/windows-7-network-awareness/).

!!! info
    [Appendix K: Network Connectivity Status Indicator and Resulting Internet Communication](https://technet.microsoft.com/en-us/library/cc766017%28WS.10%29.aspx)

## Couldn't connect to the update service

![](assets/faq/could-not-connect-update-service.png)
> We couldn't connect to the update service. We'll try again later, or you can check now. If it still doesn't work, make sure you're connected to the Internet.

If you've got this message when you want to process a Windows Update, there's maybe a problem with some hosts and/or
firewall rules that need to be updated:

* First remove all WindowsSpyBlocker firewall rules (with the executable) and check again.
If it works, [please report this issue](reporting-issue.md).
* Otherwise remove WindowsSpyBlocker hosts and check again.
If it works [please report this issue](reporting-issue.md).
* Otherwise this is probably an issue with your ISP

!!! tip
    Several tools are available to update offline:
    
    * [WSUS Offline Update](http://www.wsusoffline.net/): Using "WSUS Offline Update" (formerly known as "ct offline update" or "DIY Service Pack"), you can update any computer running Microsoft Windows safely, quickly and without an Internet connection.
    * [AutoPatcher](http://www.autopatcher.com/): Combines the advantage of both Windows Update (presentation and description of updates and automated installation), and the special administrative updates (portability and installation without the need of an Internet connection).
    * [Portable Update](http://www.portableupdate.com/): Updating a Microsoft Windows computer in a completely disconnected environment.
    * [WHDownloader](http://forums.mydigitallife.info/threads/66243-WHDownloader-Download): Formerly called the Windows Hotfix Downloader, is a lightweight and easy to use downloader used for finding and applying the latest Microsoft Windows updates.

## What is NCSI?

The NCSI is used within the Network Awareness API and shows the Internet connectivity with the Network Connection
Status Icon in the system tray. This mechanism can be configured by registry keys of the "Network Location Awareness"
service.

The internet connectivity is determined by four steps:

![](assets/faq/ncsi-graph.png)

In the first step, an IPv4 HTTP request is compared to a known string stored in the registry. If the request returns
the expected characters, the Internet connection is considered to be available. If the request fails, the same
mechanism is used with an IPv6 URL. If both fail, the third step tries to resolve an IPv4 DNS name and, if this fails
again, an IPv6 DNS resolution is used. If all four steps fail, then the Internet connection is considered to be not
available.

!!! quote
    [http://www.codeproject.com/Tips/1077317/Test-for-Internet-Connectivity-the-Windows-Way](http://www.codeproject.com/Tips/1077317/Test-for-Internet-Connectivity-the-Windows-Way)

## Antivirus complains about WindowsSpyBlocker

Releases of WindowsSpyBlocker are scanned by [VirusTotal](https://www.virustotal.com) and a link is provided in the
description of each release.

Every detections found by VirusTotal scan are generic. Most likely based on a heuristic detection.
Heuristics are more prone to false-positive detections.

This [happens quite often](https://github.com/golang/go/issues?utf8=%E2%9C%93&q=is%3Aissue%20antivirus) with programs
written in [Golang](https://golang.org/). The best you can do is to
[report this](https://github.com/crazy-max/WindowsSpyBlocker/issues/82#issuecomment-337611345) to your
Antivirus software vendor.

But if the detection is legitimate, you can still [report this issue](reporting-issue.md).
