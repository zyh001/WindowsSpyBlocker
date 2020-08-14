# DNSCrypt

!!! info
    DNSCrypt blocking rules available at [{{ config.repo_url }}tree/master/data/dnscrypt]({{ config.repo_url }}tree/master/data/firewall)

[DNSCrypt](https://dnscrypt.org/) is a protocol for securing communications between a client and a DNS resolver.
With this tool you can blacklist some domains with the plugin
[libdcplugin_example_ldns_blocking](https://github.com/jedisct1/dnscrypt-proxy#plugins) and add domains with
leading and trailing wildcards.

To install DNSCrypt on Windows, read the
[instructions](https://github.com/dnscrypt/dnscrypt-proxy/wiki/Installation-Windows) on the official
GitHub repository.

Copy the content of the dnscrypt files in the repository in a file called for example `C:\blacklisted-domains.txt`
and enter this command:

```text
dnscrypt-proxy -R <name> --plugin=libdcplugin_example_ldns_blocking.dll,--domains=C:\blacklisted-domains.txt
```

Replace `<name>` with a [public DNS resolvers supporting DNSCrypt](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/public-resolvers.md)
you want to use. Note its name in the first column (for example: `dnscrypt.org-fr`).
