Minifirewall
=========

Minifirewall is shellscripts for easy firewalling on a standalone server
we used nftables https://wiki.nftables.org/ designed for recent Linux kernel
See https://gitea.evolix.org/evolix/minifirewall

## Install

~~~
install -m 0700 minifirewall.service /etc/systemd/system/minifirewall.service
install -m 0700 minifirewall-start.sh /usr/local/sbin/minifirewall-start.sh
install -m 0700 minifirewall-stop.sh /usr/local/sbin/minifirewall-stop.sh
install -m 0600 minifirewall.conf /etc/default/minifirewall
~~~

## Config

Edit /etc/default/minifirewall file:

* If your interface is not _eth0_, change *INT* variable
* Modify *INTLAN* variable, probably with your *IP/32* or your local network if you trust it
* Set your trusted and privilegied IP addresses in *TRUSTEDIPS* and *PRIVILEGIEDIPS* variables
* Authorize your +public+ services with *SERVICESTCP1* and *SERVICESUDP1* variables
* Authorize your +semi-public+ services (only for *TRUSTEDIPS* and *PRIVILEGIEDIPS* ) with *SERVICESTCP2* and *SERVICESUDP2* variables
* Authorize your +private+ services (only for *TRUSTEDIPS* ) with *SERVICESTCP3* and *SERVICESUDP3* variables
* Configure your authorizations for external services : DNS, HTTP, HTTPS, SMTP, SSH, NTP

## Usage

~~~
systemctl start/stop/restart minifirewall.service
~~~

If you want to add minifirewall in boot sequence:

~~~
systemctl enable minifirewall
~~~

## License

This is an [Evolix](https://evolix.com) project and is licensed
under the GPLv3, see the [LICENSE](LICENSE) file for details.
