<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use Illuminate\Support\Facades\Session;

trait RegisterPublicKeyCredentialViewTests
{
    /** @test */
    public function the_public_key_credential_registration_page_uses_blade_views(): void
    {
        $this->enableSudoMode();

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.credentials.register_public_key'));

        /** @var PublicKeyCredentialCreationOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options = unserialize(Session::get('auth.mfa_setup.public_key_credential_creation_options'), [PublicKeyCredentialCreationOptions::class]));

        $response->assertViewIs('auth.settings.confirm_public_key');
        $response->assertViewHas('options', $options);
        $response->assertViewHas('randomName');
    }
}
