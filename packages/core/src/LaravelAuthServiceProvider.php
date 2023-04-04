<?php

namespace ClaudioDekker\LaravelAuth;

use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract;
use ClaudioDekker\LaravelAuth\Methods\Totp\GoogleTwoFactorAuthenticator;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyWebAuthn;
use Illuminate\Support\ServiceProvider;

class LaravelAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'laravel-auth');

        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/laravel-auth.php' => config_path('laravel-auth.php')], 'laravel-auth-package');
            $this->publishes([__DIR__.'/../lang' => $this->languagePath('vendor/laravel-auth')], 'laravel-auth-package');

            $this->registerMigrations();
        }
    }

    /**
     * Register the service provider.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/laravel-auth.php', 'laravel-auth');

        $this->app->bind(TotpContract::class, GoogleTwoFactorAuthenticator::class);
        $this->app->bind(WebAuthnContract::class, SpomkyWebAuthn::class);

        LaravelAuth::useUserModel(
            config('laravel-auth.models.user')
        );
    }

    /**
     * Register the Laravel Auth migration files.
     */
    protected function registerMigrations(): void
    {
        if (LaravelAuth::$runsMigrations) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
    }

    /**
     * Determines the path to the application's language files.
     */
    protected function languagePath(string $path): string
    {
        return function_exists('lang_path') ? lang_path($path) : resource_path('lang/'.$path);
    }
}
