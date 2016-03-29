# Windows Spy Blocker

Rules to block Windows spy / telemetry.

## Usage

* ``hostsBlockWindowsSpy.txt`` : Block Windows Spy / Telemetry
* ``hostsBlockWindowsUpdate.txt`` : Block Windows Update
* ``hostsBlockWindowsExtra.txt`` : Block third party applications

Copy / paste the content of the above files in your Windows hosts file located in ``C:\Windows\System32\drivers\etc\hosts``.<br />

You can use the [HostsMan](http://www.abelhadigital.com/hostsman) freeware to keep update your hosts file.<br />
I have created a git hook to publish the hosts files to my personal website :
* [http://www.crazyws.fr/hostsBlockWindowsSpy.txt](http://www.crazyws.fr/hostsBlockWindowsSpy.txt)
* [http://www.crazyws.fr/hostsBlockWindowsUpdate.txt](http://www.crazyws.fr/hostsBlockWindowsUpdate.txt)
* [http://www.crazyws.fr/hostsBlockWindowsExtra.txt](http://www.crazyws.fr/hostsBlockWindowsExtra.txt)

Some hosts are not blocked and required a top level application.<br />
For example you can use [Proxifier](https://www.proxifier.com/) software to block Microsoft spy.<br />
Copy the content of the proxifier files in the repository in a blocked rule :

![](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/proxifier_rule2.png)

## Sources

I use ESET Smart Security firewall and Wireshark to make this hosts files and these websites/repositories :

* http://cyberwarzone.com/block-these-ips-to-stop-microsoft-from-snooping-on-your-windows-10-device
* https://github.com/10se1ucgo/DisableWinTracking
* https://github.com/Nummer/Destroy-Windows-10-Spying
* https://github.com/WindowsLies/BlockWindows

## License

LGPL. See ``LICENSE`` for more details.
