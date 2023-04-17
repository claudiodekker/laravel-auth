<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\LaravelAuthServiceProvider;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use ClaudioDekker\LaravelAuth\Tests\_fixtures\FakeUser;
use ClaudioDekker\LaravelAuth\Tests\TestCase;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Schema;

/**
 * @backupStaticAttributes enabled
 */
class LaravelAuthTest extends TestCase
{
    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app)
    {
        return [];
    }

    protected function tearDown(): void
    {
        LaravelAuth::$runsMigrations = true;

        parent::tearDown();
    }

    /** @test */
    public function it_loads_migration_by_default(): void
    {
        $this->app->register(LaravelAuthServiceProvider::class);
        $this->artisan('migrate');

        $this->assertTrue(Schema::hasTable('multi_factor_credentials'));
    }

    /** @test */
    public function it_skips_loading_migrations_when_ignored(): void
    {
        LaravelAuth::ignoreMigrations();

        $this->app->register(LaravelAuthServiceProvider::class);
        $this->artisan('migrate');

        $this->assertFalse(Schema::hasTable('multi_factor_credentials'));
    }

    /** @test */
    public function it_uses_the_included_multi_factor_credential_model_by_default(): void
    {
        $this->assertSame(LaravelAuth::multiFactorCredentialModel(), MultiFactorCredential::class);
        $this->assertInstanceOf(MultiFactorCredential::class, LaravelAuth::multiFactorCredential());
    }

    /** @test */
    public function it_can_customize_the_multi_factor_credential_model(): void
    {
        LaravelAuth::useMultiFactorCredentialModel(User::class);

        $this->assertSame(LaravelAuth::multiFactorCredentialModel(), User::class);
        $this->assertInstanceOf(User::class, LaravelAuth::multiFactorCredential());
    }

    /** @test */
    public function it_uses_the_authentication_guard_defined_user_model_by_default(): void
    {
        $this->assertSame(LaravelAuth::userModel(), User::class);
        $this->assertInstanceOf(User::class, LaravelAuth::user());
    }

    /** @test */
    public function it_can_customize_the_user_model(): void
    {
        LaravelAuth::useUserModel(FakeUser::class);

        $this->assertSame(LaravelAuth::userModel(), FakeUser::class);
        $this->assertInstanceOf(FakeUser::class, LaravelAuth::user());
    }
}
