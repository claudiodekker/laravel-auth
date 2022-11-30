# Laravel Auth (for Blade; barebones edition)
Rich authentication scaffolding for any blade-based Laravel application.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/claudiodekker/laravel-auth-bladebones.svg?style=flat-square)](https://packagist.org/packages/claudiodekker/laravel-auth-bladebones)
[![GitHub Tests Action Status](https://img.shields.io/github/workflow/status/claudiodekker/laravel-auth-bladebones/run-tests?label=tests)](https://github.com/claudiodekker/laravel-auth-bladebones/actions?query=workflow%3Arun-tests+branch%3Amaster)
[![GitHub Code Style Action Status](https://img.shields.io/github/workflow/status/claudiodekker/laravel-auth-bladebones/Check%20&%20fix%20styling?label=code%20style)](https://github.com/claudiodekker/laravel-auth-bladebones/actions?query=workflow%3A"Check+%26+fix+styling"+branch%3Amaster)
[![Code Quality Score](https://img.shields.io/scrutinizer/g/claudiodekker/laravel-auth-bladebones.svg?style=flat-square)](https://scrutinizer-ci.com/g/claudiodekker/laravel-auth-bladebones)
[![Total Downloads](https://img.shields.io/packagist/dt/claudiodekker/laravel-auth-bladebones.svg?style=flat-square)](https://packagist.org/packages/claudiodekker/laravel-auth-bladebones)

These days, most (web)applications no longer have just a simple username-password login form; they require you to think about password strength, two-factor authentication, 
the ability to recover your account with all of this set up, and as of more recently even the ability to log in without any password at all, using Passkeys.
It goes without saying, that it takes a lot of effort to implement authentication yourself, and especially so if you want to do it in a way that is secure and easy to maintain.

### What in the box?

This package aims to provide a simple, yet powerful authentication scaffolding for any Laravel application, and contains everything you would need in a modern authentication system:
- Basic email-password or username-password based authentication.
- Passkey-based ("passwordless") authentication.
- Two factor authentication for password-based users (TOTP, Security Keys).
- Email verification, either directly after registration or manually.
- Sudo-mode, allowing the user to temporarily elevate their privileges and perform sensitive actions.
- Account recovery (requires the generation of recovery codes).
- A rich set of authentication events, such as `MultiFactorChallenged`, `AccountRecoveryFailed`, etc.

Furthermore, this library is designed to be flexible. It generates controllers into your application that contain only methods that are intended to be customized, with [all core authentication logic](https://github.com/claudiodekker/laravel-auth)
existing within the parent controller that they extend. This way, you can easily customize the authentication flow to your liking, while still receiving updates / fixes to [the core logic itself](https://github.com/claudiodekker/laravel-auth).
While this might seem somewhat scary, we've also included extensive (and customizable) feature tests, which are installed into your application at the same time.

## Installation

You can install the package via composer:

```bash
composer require claudiodekker/laravel-auth-bladebones
```

Once installed, you'll want to generate the authentication scaffolding itself.
Do note that this will override some existing files, such as the `User` model and the `routes/web.php` file.

```bash
php artisan auth:generate
```

Optionally, you can also publish the configuration file and translations:
    
```bash
 php artisan vendor:publish --tag "laravel-auth-package"
```

## Why is this better than \<other package>?

To make a long story short; it isn't. Not necessarily.

There's a lot of packages out there that do a great job at providing authentication. However, in my opinion, almost all of them are either:
- Missing features you'd want or expect (e.g. passkeys, two-factor authentication).
- Containing features you don't always want or need (e.g. team management).
- Missing tests, or don't cover all of the features they provide on application level.
- Too opinionated, or not flexible / customizable enough.
- No longer being actively maintained.

## Testing

To run this package's test (scaffolding generation etc.), you can run:

``` bash
composer test
```

However, to run your own application's tests (after generating the scaffolding), you can run:

``` bash
php artisan test
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
