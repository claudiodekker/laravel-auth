<?php

namespace ClaudioDekker\LaravelAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

class LaravelAuth
{
    /**
     * Indicates if the Laravel Auth migrations will be run.
     */
    public static bool $runsMigrations = true;

    /**
     * The Multi-Factor Credential model class name.
     */
    protected static string $multiFactorCredentialModel = MultiFactorCredential::class;

    /**
     * The User model class name.
     */
    protected static ?string $userModel = null;

    /**
     * Configure Laravel Auth to not register its migrations.
     */
    public static function ignoreMigrations(): static
    {
        static::$runsMigrations = false;

        return new static();
    }

    /**
     * Set the User model class name.
     */
    public static function useUserModel(string $model = null): void
    {
        static::$userModel = $model;
    }

    /**
     * Get the User model class name.
     */
    public static function userModel(): string
    {
        if (! is_null(static::$userModel)) {
            return static::$userModel;
        }

        $guard = Config::get('auth.defaults.guard');
        $provider = Config::get('auth.guards.'.$guard.'.provider');

        return Config::get('auth.providers.'.$provider.'.model');
    }

    /**
     * Get a new Multi-Factor Credential model instance.
     */
    public static function user(): Model&Authenticatable
    {
        $model = static::userModel();

        return new $model();
    }

    /**
     * Set the Multi-Factor Credential model class name.
     */
    public static function useMultiFactorCredentialModel(string $model): void
    {
        static::$multiFactorCredentialModel = $model;
    }

    /**
     * Get the Multi-Factor Credential model class name.
     */
    public static function multiFactorCredentialModel(): string
    {
        return static::$multiFactorCredentialModel;
    }

    /**
     * Get a new Multi-Factor Credential model instance.
     *
     * @return \ClaudioDekker\LaravelAuth\MultiFactorCredential
     */
    public static function multiFactorCredential()
    {
        $model = static::multiFactorCredentialModel();

        return new $model();
    }
}
