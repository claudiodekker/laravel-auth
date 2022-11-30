<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;

trait ViewLoginPageTests
{
    /** @test */
    public function the_login_page_can_be_viewed(): void
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'configured.rpid');
        $this->mockWebauthnChallenge($challenge = 'cPMfYjCIb804eqvknNWAqA');
        $response = $this->get(route('login'));

        $response->assertOk();
        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options = unserialize(Session::get('auth.login.passkey_authentication_options'), [PublicKeyCredentialRequestOptions::class]));
        $this->assertSame([
            'challenge' => $challenge,
            'rpId' => 'configured.rpid',
            'userVerification' => 'required',
        ], $options->jsonSerialize());
    }

    /** @test */
    public function the_login_page_cannot_be_viewed_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->get(route('login'));

        $response->assertRedirect(RouteServiceProvider::HOME);
        $response->assertSessionMissing('auth.login.passkey_authentication_options');
    }
}
