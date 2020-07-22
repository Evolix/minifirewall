Minifirewall
=========

Minifirewall is shellscripts for easy firewalling on a standalone server
we used netfilter/iptables http://netfilter.org/ designed for recent Linux kernel
See https://gitea.evolix.org/evolix/minifirewall

## Install

~~~
install -m 0700 minifirewall /etc/init.d/minifirewall
install -m 0600 minifirewall.conf /etc/default/minifirewall
~~~

## Config

Edit /etc/default/minifirewall file:

* If your interface is not _eth0_, change *INT* variable
* If you don't IPv6 : *IPv6=off*
* Modify *INTLAN* variable, probably with your *IP/32* or your local network if you trust it
* Set your trusted and privilegied IP addresses in *TRUSTEDIPS* and *PRIVILEGIEDIPS* variables
* Authorize your +public+ services with *SERVICESTCP1* and *SERVICESUDP1* variables
* Authorize your +semi-public+ services (only for *TRUSTEDIPS* and *PRIVILEGIEDIPS* ) with *SERVICESTCP2* and *SERVICESUDP2* variables
* Authorize your +private+ services (only for *TRUSTEDIPS* ) with *SERVICESTCP3* and *SERVICESUDP3* variables
* Configure your authorizations for external services : DNS, HTTP, HTTPS, SMTP, SSH, NTP
* Add your specific rules

## Usage

~~~
/etc/init.d/minifirewall start/stop/restart
~~~

If you want to add minifirewall in boot sequence:

~~~
systemctl enable minifirewall
~~~

## Ban a whole AS

### Automatic way using an API

Set the AS number you want to ban in BANNEDASNS.

### Manual way

The manual way is here only for reference.

First find the AS for one IP address.
~~~
$ whois IP | grep origin:
Or if no result, use a specific whois server
$ whois -h whois.radb.net IP | grep origin:
Or if no result, use a specific whois server
$ whois -h whois.cymru.com IP
~~~

Then, get the routes of this AS.
~~~
$ whois -i origin ASNUMBER | grep route:
Or if no result, use a specific whois server
$ whois -h whois.radb.net -i origin ASNUMBER | grep route:
Or if no result, use a specific API
$ curl -qs https://asn.ipinfo.app/api/text/list/ASNUMBER
~~~

Finally, add a kernel set and DROP the set.

~~~
# ipset -N ASNUMBER hash:net family inet
# ipset -A ASNUMBER 192.0.2.0/24
# ipset -A ASNUMBER 198.51.100.0/24
# iptables -A INPUT -m set --match-set ASNUMBER src -j DROP
~~~


## License

This is an [Evolix](https://evolix.com) project and is licensed
under the GPLv3, see the [LICENSE](LICENSE) file for details.
