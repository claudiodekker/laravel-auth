<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use Illuminate\Support\Facades\Session;

trait RegisterTotpCredentialViewTests
{
    /** @test */
    public function the_time_based_one_time_password_credential_registration_confirmation_page_uses_blade_views(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', 'test');

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.credentials.register_totp.confirm'));

        $response->assertViewIs('auth.settings.confirm_totp');
        $response->assertViewHas('qrImage');
        $response->assertViewHas('randomName');
        $response->assertViewHas('secret', 'test');
    }
}
