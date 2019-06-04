# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant::DEFAULT_SERVER_URL.replace('https://vagrantcloud.com')

# Load ~/.VagrantFile if exist, permit local config provider
vagrantfile = File.join("#{Dir.home}", '.VagrantFile')
load File.expand_path(vagrantfile) if File.exists?(vagrantfile)

Vagrant.configure('2') do |config|
  config.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: [ '.vagrant', '.git' ]
  config.ssh.shell="/bin/sh"

  $install = <<SCRIPT
DEBIAN_FRONTEND=noninteractive apt-get -yq install iptables
ln -fs /vagrant/minifirewall /etc/init.d/minifirewall
ln -fs /vagrant/minifirewall.conf /etc/default/minifirewall
SCRIPT

  config.vm.define "minifirewall" do |node|
    node.vm.hostname = "minifirewall"
    node.vm.box = "debian/stretch64"
    config.vm.provision "install", type: "shell", :inline => $install
  end

end
