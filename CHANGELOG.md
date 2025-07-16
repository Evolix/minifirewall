The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project **does not adhere to [Semantic Versioning](http://semver.org/spec/v2.0.0.html)**.

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

* Remove secondary Evolix office IPs from TRUSTEDIPS

### Fixed

### Security

## [25.05] - 2025-05-22

### Added

* support NO_COLOR env variable (cf. https://no-color.org/)
* Allow Docker containers on the default bridge (docker0) to talk to host services

### Changed

* blacklist-*.sh scripts: use "ipset restore" instead of multiple "ipset add"
* declare NEEDRESTRICT chain sooner
* display Ok/Error on each line
* extract is_color_enabled() function
* review blacklist-*.sh scripts: use ipset, MD5 verification, etc.

### Removed

* Don't expose Docker services via Public/Semi-public/Private macros

## [24.07] - 2024-07-11

### Added

* safe-start and safe-restart
* Chain MINIFW-DOCKER-INPUT-MANUAL for more granular/manual filtering of incoming traffic to services inside docker

### Changed

### Deprecated

### Removed

* Removed RELATED state match

### Fixed

* fix interactive mode detection

### Security


## [23.07] - 2023-07-04

### Added

* new "check-active-config" command to check if the active configuration is th e same as the one persisted to disk

### Changed

* capture cmp(1) error output
* early error if script is not run as root
* extract "include_files" function
* print help/usage with list of possible commands

## [23.02] - 2023-02-01

* Export status without colors (to keep clean diffs)

## [22.06] - 2022-06-06

### Changed

* Configure sysctl values to IPv6 when applicable

### Fixed

* status output (number of # in headers)

## [22.05] - 2022-05-10

#### Fixed

* status output (number of # in headers)

## [22.04] - 2022-04-28

### Added

* markers for each section of status output
* store and compare state between restart
* colorize output if terminal supports colors
* simple syslog logging
* "version" action

### Changed

* use long options in some places
* output is normalized
* source legacy config after macros but before DROP policy
* source configuration only for valid actions
* improve legacy config parsing

### Fixed

* force remove temporary files
