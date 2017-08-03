Minifirewall is shellscripts for easy firewalling on a standalone server
we used netfilter/iptables http://netfilter.org/ designed for recent Linux kernel
See https://forge.evolix.org/projects/minifirewall

# Install

Copy minifirewall script and config :

~~~
cp minifirewall /usr/local/sbin
ln -s /usr/local/sbin/minifirewall /sbin
cp minifirewall.conf /etc/default/minifirewall
~~~

## Systemd

Copy systemd service in /etc/systemd/system :

~~~
cp minifirewall.service /etc/systemd/systemd/
systemctl daemon-reload
systemctl enable minifirewall
~~~

## Sysvinit

Make a link to minifirewall script (SysVinit compatible) in /etc/init.d :

~~~
ln -s /usr/local/sbin/minifirewall /etc/init.d
update-rc.d defaults minifirewall
~~~
