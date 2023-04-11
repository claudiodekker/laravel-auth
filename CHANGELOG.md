# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/claudiodekker/laravel-auth/compare/v0.2.0...HEAD)

### Added

- Account Security indicator ([#26](https://github.com/claudiodekker/laravel-auth/pull/26))
- Core: Add support for pruning "claimed" users that never finish sign-up ([#27](https://github.com/claudiodekker/laravel-auth/pull/27))
- Add docblock-level `@see`-references ([#29](https://github.com/claudiodekker/laravel-auth/pull/29))
- Core: Skip the recovery code challenge when no codes exist ([#30](https://github.com/claudiodekker/laravel-auth/pull/30))

### Optimized

- Improved dev-dependencies ([#39](https://github.com/claudiodekker/laravel-auth/pull/39))
- Remove ext-json requirement ([#41](https://github.com/claudiodekker/laravel-auth/pull/41))

### Fixed

- Core: Fixed timing-related test regression ([#24](https://github.com/claudiodekker/laravel-auth/pull/24))
- Bladebones: Recovery Code must be exactly 10 characters ([#28](https://github.com/claudiodekker/laravel-auth/pull/28))
- Core: Public Key Challenge - Update signature count ([#31](https://github.com/claudiodekker/laravel-auth/pull/31))

### Changed

- Improve Rate Limiting ([#32](https://github.com/claudiodekker/laravel-auth/pull/32))
- Added Larastan & improved violations ([#36](https://github.com/claudiodekker/laravel-auth/pull/36))

### Removed

- Revert model DB connection customization ([#38](https://github.com/claudiodekker/laravel-auth/pull/38))


## [v0.2.0](https://github.com/claudiodekker/laravel-auth/compare/v0.1.2...v0.2.0) - 2023-04-03

### Added

- PHP 8.2 Support ([#23](https://github.com/claudiodekker/laravel-auth/pull/23))
- Laravel 10 Support ([#23](https://github.com/claudiodekker/laravel-auth/pull/23))

### Fixed

- Core: Fixed timing-related test regression ([#23](https://github.com/claudiodekker/laravel-auth/pull/23))

### Changed

- Moved `claudiodekker/laravel-auth` v0.1.0 into this monorepo
- Moved `claudiodekker/laravel-auth-bladebones` v0.1.2 into this monorepo
- Updated this `CHANGELOG.md` to reflect previous non-monorepo releases
- Bladebones: Changed dependency from `claudiodekker/laravel-auth` to `claudiodekker/laravel-auth-core`
- Bladebones: Improved generator styling, as per Laravel Pint standards ([#23](https://github.com/claudiodekker/laravel-auth/pull/23))
- Core: Improved tests to use translations instead of string matches ([#23](https://github.com/claudiodekker/laravel-auth/pull/23))


## [v0.1.2](https://github.com/claudiodekker/laravel-auth/compare/v0.1.1...v0.1.2) - 2022-11-30

### Fixed

- Bladebones: Add Laravel Pint linting to scaffolding-created files ([#1](https://github.com/claudiodekker/laravel-auth-bladebones/pull/1))
- Bladebones: Fix imports on generated files ([#2](https://github.com/claudiodekker/laravel-auth-bladebones/pull/2))


## [v0.1.1](https://github.com/claudiodekker/laravel-auth/compare/v0.1.0...v0.1.1) - 2022-11-30

### Fixed

- Bladebones: Widen the version constraint to allow `claudiodekker/laravel-auth` >=v0.1 <1.0.0


## [v0.1.0](https://github.com/claudiodekker/laravel-auth/releases/tag/v0.1.0) - 2022-11-30

### Added

- Initial release of `claudiodekker/laravel-auth`
- Initial release of `claudiodekker/laravel-auth-bladebones`
