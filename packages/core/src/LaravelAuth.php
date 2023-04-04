<?php

namespace ClaudioDekker\LaravelAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class LaravelAuth
{
    /**
     * Indicates if the Laravel Auth migrations will be run.
     */
    public static bool $runsMigrations = true;

    /**
     * The Multi-Factor Credential model class name.
     */
    public static string $multiFactorCredentialModel = MultiFactorCredential::class;

    /**
     * The User model class name.
     */
    public static string $userModel;

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
    public static function useUserModel(string $model): void
    {
        static::$userModel = $model;
    }

    /**
     * Get the User model class name.
     */
    public static function userModel(): string
    {
        return static::$userModel;
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
        return new static::$multiFactorCredentialModel();
    }
}
