# Laravel Auth
Rich authentication scaffolding for any blade-based Laravel application.

<p>
    <a href="https://github.com/claudiodekker/laravel-auth/actions"><img src="https://github.com/claudiodekker/laravel-auth/workflows/tests/badge.svg" alt="Build Status"></a>
    <a href="https://packagist.org/packages/claudiodekker/laravel-auth-core"><img src="https://img.shields.io/packagist/dt/claudiodekker/laravel-auth-core" alt="Total Downloads"></a>
    <a href="https://packagist.org/packages/claudiodekker/laravel-auth-core"><img src="https://img.shields.io/packagist/v/claudiodekker/laravel-auth-core" alt="Latest Stable Version"></a>
    <a href="https://packagist.org/packages/claudiodekker/laravel-auth-core"><img src="https://img.shields.io/packagist/l/claudiodekker/laravel-auth" alt="License"></a>
</p>

## About Laravel Auth

In today's digital landscape, the authentication process for most web applications has evolved beyond basic username-password logins.
Modern authentication systems must consider password strength, two-factor authentication, secure account recovery, and even passwordless login methods like Passkeys. 
Implementing a robust, secure, and maintainable authentication solution can be a challenging task, requiring significant effort and expertise.

This monorepo contains an authentication library, along with a collection of adapter packages that leverage the library, to deliver a comprehensive authentication framework for your applications.

### Features

- Basic email-password or username-password based authentication.
- Passkey-based ("passwordless") authentication.
- Two factor authentication for password-based users (TOTP, Security Keys).
- Email verification, either directly after registration or manually.
- Sudo-mode, allowing the user to temporarily elevate their privileges and perform sensitive actions.
- Account recovery (requires the generation of recovery codes).
- A rich set of authentication events, such as `MultiFactorChallenged`, `AccountRecoveryFailed`, etc.

## Adapters & Usage

To use this authentication library, you'll likely want to install an adapter package, which use the 'core' package internally.
Here are some of the available adapter packages:

| Package                  | Description                                                | Composer Require                                                      |
|--------------------------|------------------------------------------------------------|-----------------------------------------------------------------------|
| Laravel Auth Bladebones  | An extremely basic, unthemed Blade adapter                 | `composer require claudiodekker/laravel-auth-bladebones`              |
| ~~Laravel Auth Blade~~   | ~~A Blade adapter that includes Tailwind themed views~~    | ~~`composer require claudiodekker/laravel-auth-blade`~~ Coming soon   |
| ~~Laravel Auth Inertia~~ | ~~An Inertia adapter that includes Tailwind themed views~~ | ~~`composer require claudiodekker/laravel-auth-inertia`~~ Coming soon |

### Creating your own adapter package

If you're looking to develop your own adapter, we recommend using the [Bladebones adapter](https://github.com/claudiodekker/laravel-auth-bladebones)
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
