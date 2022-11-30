<?php

namespace ClaudioDekker\LaravelAuth\Tests;

use ClaudioDekker\LaravelAuth\LaravelAuthServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\RateLimiter;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    use RefreshDatabase;

    /**
     * Define database migrations.
     *
     * @return void
     */
    protected function defineDatabaseMigrations()
    {
        $this->loadLaravelMigrations();
    }

    /**
     * Define environment setup.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function getEnvironmentSetUp($app)
    {
        config()->set('database.default', 'testbench');
        config()->set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app)
    {
        return [
            LaravelAuthServiceProvider::class,
        ];
    }

    /**
     * Mocks the container-bound Rate Limiter instance
     * with one that has exceeded the limit.
     */
    protected function mockRateLimitExceeded(): void
    {
        $mock = RateLimiter::partialMock();

        $mock->shouldReceive('tooManyAttempts')->andReturn(true);
        $mock->shouldReceive('availableIn')->andReturn(75);
        $mock->shouldReceive('hit')->andReturn(1);
    }
}
