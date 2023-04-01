<?php

namespace ClaudioDekker\LaravelAuthBladebones\Tests;

use ClaudioDekker\LaravelAuthBladebones\LaravelAuthBladebonesServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app)
    {
        return [
            LaravelAuthBladebonesServiceProvider::class,
        ];
    }
}
