The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project **does not adhere to [Semantic Versioning](http://semver.org/spec/v2.0.0.html)**.

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

* status output (number of # in headers)

### Security

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