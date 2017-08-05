$ git checkout debian-sid
$ debmake -t
... edit rules, changelog, ...
$ dpkg-buildpackage
