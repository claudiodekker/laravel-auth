<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp;

use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract as Authenticator;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Session;

trait CancelTotpCredentialRegistrationTests
{
    /** @test */
    public function the_user_can_cancel_the_time_based_one_time_password_credential_registration_process(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', App::make(Authenticator::class)->generateSecret());

        $response = $this->actingAs($this->generateUser())
            ->delete(route('auth.credentials.register_totp.cancel'));

        $response->assertRedirect(route('auth.settings'));
        $this->assertFalse(Session::has('auth.mfa_setup.pending_totp_secret'));
    }

    /** @test */
    public function the_user_cannot_cancel_the_time_based_one_time_password_credential_registration_process_when_no_longer_in_sudo_mode(): void
    {
        Session::put('auth.mfa_setup.pending_totp_secret', App::make(Authenticator::class)->generateSecret());

        $response = $this->actingAs($this->generateUser())
            ->delete(route('auth.credentials.register_totp.cancel'));

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('auth.mfa_setup.pending_totp_secret'));
    }
}
