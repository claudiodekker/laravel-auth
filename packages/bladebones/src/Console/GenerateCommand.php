<?php

namespace ClaudioDekker\LaravelAuthBladebones\Console;

use ClaudioDekker\LaravelAuth\Console\GenerateCommand as BaseGenerateCommand;

class GenerateCommand extends BaseGenerateCommand
{
    /**
     * Determines the path to this package.
     *
     * @return string
     */
    protected function determinePackagePath(): string
    {
        return dirname(__DIR__, 2);
    }

    /**
     * Installs the package's authentication routes.
     *
     * @return void
     */
    protected function installRoutes(): void
    {
        $this->copy('routes/web.stub', base_path('routes/web.php'));
    }

    /**
     * Installs the package's authentication tests.
     *
     * @return void
     */
    protected function installTests(): void
    {
        $this->generate('Tests.AuthenticationTest', base_path('tests/Feature/AuthenticationTest.php'));
    }

    /**
     * Installs the package's authentication views.
     *
     * @return void
     */
    protected function installViews(): void
    {
        $this->copy('views/challenges/multi_factor.blade.stub', resource_path('views/auth/challenges/multi_factor.blade.php'));
        $this->copy('views/challenges/recovery.blade.stub', resource_path('views/auth/challenges/recovery.blade.php'));
        $this->copy('views/challenges/sudo_mode.blade.stub', resource_path('views/auth/challenges/sudo_mode.blade.php'));
        $this->copy('views/home.blade.stub', resource_path('views/home.blade.php'));
        $this->copy('views/login.blade.stub', resource_path('views/auth/login.blade.php'));
        $this->copy('views/recover-account.blade.stub', resource_path('views/auth/recover-account.blade.php'));
        $this->copy('views/register.blade.stub', resource_path('views/auth/register.blade.php'));
        $this->copy('views/settings/confirm_public_key.blade.stub', resource_path('views/auth/settings/confirm_public_key.blade.php'));
        $this->copy('views/settings/confirm_recovery_codes.blade.stub', resource_path('views/auth/settings/confirm_recovery_codes.blade.php'));
        $this->copy('views/settings/confirm_totp.blade.stub', resource_path('views/auth/settings/confirm_totp.blade.php'));
        $this->copy('views/settings/credentials.blade.stub', resource_path('views/auth/settings/credentials.blade.php'));
        $this->copy('views/settings/recovery_codes.blade.stub', resource_path('views/auth/settings/recovery_codes.blade.php'));
    }
}
