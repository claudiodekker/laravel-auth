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
        LaravelAuth::useUserModel(
            config('auth.providers.users.model', 'App\\Models\\User')
        );

        $this->registerResources();
        $this->registerMigrations();
        $this->registerPublishing();
    }

    /**
     * Register the service provider.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/laravel-auth.php', 'laravel-auth');

        $this->app->bind(TotpContract::class, GoogleTwoFactorAuthenticator::class);
        $this->app->bind(WebAuthnContract::class, SpomkyWebAuthn::class);
    }

    /**
     * Register the Laravel Auth resources.
     */
    protected function registerResources(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'laravel-auth');
    }

    /**
     * Register the Laravel Auth migration files.
     */
    protected function registerMigrations(): void
    {
        if ($this->app->runningInConsole() && LaravelAuth::$runsMigrations) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
    }

    /**
     * Register the package's publishable resources.
     */
    protected function registerPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/laravel-auth.php' => config_path('laravel-auth.php'),
            ], 'laravel-auth-config');

            $this->publishes([
                __DIR__.'/../lang' => lang_path('vendor/laravel-auth'),
            ], 'laravel-auth-translations');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'laravel-auth-migrations');
        }
    }
}
