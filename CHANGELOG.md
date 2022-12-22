# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/claudiodekker/laravel-auth/compare/v0.1.0...HEAD)

### Added

- PHP 8.2 Support ([#6](https://github.com/claudiodekker/laravel-auth/pull/6))
- The Passkey-based registration flow can now be cancelled, directly releasing the claimed user ([#7](https://github.com/claudiodekker/laravel-auth/pull/7))
- `exec` generator method, providing an easy way to run cli commands ([#8](https://github.com/claudiodekker/laravel-auth/pull/8))
- New Account Security Strength Indicator ([#11](https://github.com/claudiodekker/laravel-auth/pull/11))

### Changed

- The recovery challenge will now be skipped when no codes have been configured ([#13](https://github.com/claudiodekker/laravel-auth/pull/13))

### Fixed

- fakerphp/faker 1.14: Accessing property "dateTime" is deprecated ([`ffd680a`](https://github.com/claudiodekker/laravel-auth/commit/ffd680a65746c8c0fe7384644979f1960242659e))
- Removed unnecessary `composer.lock` file ([`ffd680a`](https://github.com/claudiodekker/laravel-auth/commit/ffd680a65746c8c0fe7384644979f1960242659e))
- Fixed `README.md` shields ([`30757fc`](https://github.com/claudiodekker/laravel-auth/commit/30757fc80d6933d7dabdb2f67f7718ac08247108))
- Claimed Passkey-based user accounts that never complete sign-up will now be auto-pruned ([#7](https://github.com/claudiodekker/laravel-auth/pull/7))
- Fixed a test assertion timing bug (missing Carbon::setTestNow) ([#9](https://github.com/claudiodekker/laravel-auth/pull/9))

## [v0.1.0](https://github.com/claudiodekker/laravel-auth/releases/tag/v0.1.0) - 2022-11-30

### Added

- Initial release
