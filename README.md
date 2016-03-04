# Windows Spy Blocker

Rules to block Windows spy / telemetry.

## Usage

Copy / paste the content of ``hosts.txt`` file in your Windows hosts file located in ``C:\Windows\System32\drivers\etc\hosts``.<br /><br />

You can use the [HostsMan](http://www.abelhadigital.com/hostsman) freeware to keep update your hosts file.<br />
I have created a git hook to publish the hosts file to my personal website.<br />
Add this url to HostsMan : [http://www.crazyws.fr/HostsWindowsBlocker.txt](http://www.crazyws.fr/HostsWindowsBlocker.txt)<br /><br />

Some hosts are not blocked and required a top level application.<br />
For example you can use [Proxifier](https://www.proxifier.com/) software to block Microsoft spy.<br />
Copy the content of the ```proxifier.txt``` file in a blocked rule :

![](https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/proxifier_rule.png)

## Sources

I used ESET Smart Security firewall and Wireshark to make this hosts file and these websites/repositories :

* http://cyberwarzone.com/block-these-ips-to-stop-microsoft-from-snooping-on-your-windows-10-device
* https://github.com/10se1ucgo/DisableWinTracking
* https://github.com/Nummer/Destroy-Windows-10-Spying
* https://github.com/WindowsLies/BlockWindows

## License

LGPL. See ``LICENSE`` for more details.
