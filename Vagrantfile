# -*- mode: ruby -*-
# vi: set ft=ruby :

# Load ~/.VagrantFile if exist, permit local config provider
vagrantfile = File.join("#{Dir.home}", '.VagrantFile')
load File.expand_path(vagrantfile) if File.exists?(vagrantfile)

Vagrant.configure('2') do |config|
  config.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: [ '.vagrant', '.git' ]
  config.ssh.shell="/bin/sh"

  deps = <<SCRIPT
  DEBIAN_FRONTEND=noninteractive apt-get -yq install iptables
SCRIPT

  install = <<SCRIPT
ln -fs /vagrant/minifirewall /etc/init.d/minifirewall
ln -fs /vagrant/minifirewall.conf /etc/default/minifirewall
mkdir -p /etc/minifirewall.d
SCRIPT

  post = <<SCRIPT
sed -i "s|^TRUSTEDIPS='|TRUSTEDIPS='192.168.121.0/24 |" /etc/default/minifirewall
SCRIPT

  config.vm.define "minifirewall" do |node|
    node.vm.hostname = "minifirewall"
    node.vm.box = "debian/bookworm64"
    config.vm.provision "deps", type: "shell", inline: deps
    config.vm.provision "install", type: "shell", inline: install
    config.vm.provision "post", type: "shell", inline: post
  end

end
