# NCSI

Windows check a Microsoft site for connectivity, using the Network Connectivity Status Indicator site. NCSI performs a
DNS lookup on `www.msftncsi.com` and sends a DNS lookup request for `dns.msftncsi.com`.

You can block this probe by adding the content of the `data/<type>/extra.txt` hosts file.

But you will have a ["No Internet access" warning in your system tray](../../faq.md#no-internet-access-on-my-network-card).

To solve this issue you can use the Debian NCSI through `NCSI > Apply Debian NCSI`:

![](../../assets/app/telemetry/ncsi/apply.png)

Then you can test your internet connection the Microsoft way:

![](../../assets/app/telemetry/ncsi/test.png)
