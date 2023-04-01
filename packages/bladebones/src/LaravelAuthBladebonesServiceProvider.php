<?php

namespace ClaudioDekker\LaravelAuthBladebones;

use ClaudioDekker\LaravelAuthBladebones\Console\GenerateCommand;
use Illuminate\Support\ServiceProvider;

class LaravelAuthBladebonesServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands(GenerateCommand::class);
        }
    }

    /**
     * Register the service provider.
     */
    public function register(): void
    {
        //
    }
}
