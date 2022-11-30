<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp;

use Illuminate\Support\Facades\Session;

trait InitializeTotpCredentialRegistrationTests
{
    /** @test */
    public function the_user_can_initialize_a_new_time_based_one_time_password_credential_registration_process(): void
    {
        $this->enableSudoMode();
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_totp_secret'));

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp'));

        $response->assertRedirect(route('auth.credentials.register_totp.confirm'));
        $this->assertIsString(Session::get('auth.mfa_setup.pending_totp_secret'));
        $this->assertSame(32, strlen(Session::get('auth.mfa_setup.pending_totp_secret')));
    }

    /** @test */
    public function the_user_cannot_initialize_a_new_one_time_based_time_password_credential_registration_process_when_no_longer_in_sudo_mode(): void
    {
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_totp_secret'));

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp'));

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_totp_secret'));
    }

    /** @test */
    public function a_new_one_time_based_time_password_credential_registration_process_cannot_be_initialized_when_the_user_is_not_password_based(): void
    {
        $this->enableSudoMode();
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_totp_secret'));

        $response = $this->actingAs($this->generateUser(['has_password' => false]))
            ->post(route('auth.credentials.register_totp'));

        $response->assertForbidden();
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_totp_secret'));
    }
}
