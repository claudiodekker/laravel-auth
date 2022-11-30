<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp;

use Illuminate\Support\Facades\Session;

trait ViewTotpCredentialRegistrationConfirmationPageTests
{
    /** @test */
    public function the_user_can_view_the_time_based_one_time_password_credential_registration_confirmation_page(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', 'test');

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.credentials.register_totp.confirm'));

        $response->assertOk();
    }

    /** @test */
    public function the_user_cannot_view_the_time_based_one_time_password_credential_registration_confirmation_page_when_none_is_being_registered(): void
    {
        $this->enableSudoMode();

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.credentials.register_totp.confirm'));

        $response->assertStatus(428);
    }

    /** @test */
    public function the_user_cannot_view_the_time_based_one_time_password_credential_registration_confirmation_page_when_no_longer_in_sudo_mode(): void
    {
        Session::put('auth.mfa_setup.pending_totp_secret', 'test');

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.credentials.register_totp.confirm'));

        $response->assertRedirect(route('auth.sudo_mode'));
    }
}
