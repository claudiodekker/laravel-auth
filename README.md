# Laravel Auth (Core)
Rich authentication logic for your Laravel applications; not intended for direct use.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/claudiodekker/laravel-auth.svg)](https://packagist.org/packages/claudiodekker/laravel-auth)
[![GitHub App Tests Action Status](https://github.com/claudiodekker/laravel-auth/actions/workflows/app-tests.yml/badge.svg)](https://github.com/claudiodekker/laravel-auth/actions/workflows/app-tests.yml)
[![Github Package Tests Action Status](https://github.com/claudiodekker/laravel-auth/actions/workflows/package-tests.yml/badge.svg)](https://github.com/claudiodekker/laravel-auth/actions/workflows/package-tests.yml)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/claudiodekker/laravel-auth/fix-styling.yml?label=code%20style&logo=github&branch=master)](https://github.com/claudiodekker/laravel-auth/actions?query=workflow%3A"Check+%26+fix+styling"+branch%3Amaster)
[![Code Quality Score](https://img.shields.io/scrutinizer/g/claudiodekker/laravel-auth.svg?logo=scrutinizer)](https://scrutinizer-ci.com/g/claudiodekker/laravel-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/claudiodekker/laravel-auth.svg)](https://packagist.org/packages/claudiodekker/laravel-auth)

These days, most (web)applications no longer have just a simple username-password login form; they require you to think about password strength, two-factor authentication,
the ability to recover your account with all of this set up, and as of more recently even the ability to log in without any password at all, using Passkeys.
It goes without saying, that it takes a lot of effort to implement authentication yourself, and especially so if you want to do it in a way that is secure and easy to maintain.

### What in the box?

This package holds all the core authentication logic that's [used by adapter packages](#adapters--usage),
with the exception of the scaffolding that ends up getting installed into your application:

- Basic email-password or username-password based authentication.
- Passkey-based ("passwordless") authentication.
- Two factor authentication for password-based users (TOTP, Security Keys).
- Email verification, either directly after registration or manually.
- Sudo-mode, allowing the user to temporarily elevate their privileges and perform sensitive actions.
- Account recovery (requires the generation of recovery codes).
- A rich set of authentication events, such as `MultiFactorChallenged`, `AccountRecoveryFailed`, etc.

## Adapters & Usage

To use this authentication library, you'll want to install an adapter package instead, which all use this library as an internal dependency.
Here are some of the available adapters:

- [Laravel Auth Bladebones](https://github.com/claudiodekker/laravel-auth-bladebones)
- Laravel Auth Blade (coming soon, includes Tailwind themed views)
- Laravel Auth Inertia (coming soon, includes Tailwind themed views)

### Creating your own adapter package

If you're looking to develop your own adapter, we recommend using the [Bladebones adapter (template)](https://github.com/claudiodekker/laravel-auth-bladebones)
repository as a starting point, as it already contains all the necessary scaffolding in it's most barebones form (hence the name).

## Testing

``` bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email claudio@ubient.net instead of using the issue tracker.

This way, we can safely discuss and resolve the issue (within a reasonable timeframe), without exposing users to the unnecessary additional risk.
Once the issue is fixed and a new version is released, we'll make sure to credit you for your contribution (unless you wish to remain anonymous).

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
