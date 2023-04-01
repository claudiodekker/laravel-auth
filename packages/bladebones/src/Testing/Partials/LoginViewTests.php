<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Support\Facades\Session;

trait LoginViewTests
{
    /** @test */
    public function the_login_page_uses_blade_views(): void
    {
        $response = $this->get(route('login'));

        /** @var PublicKeyCredentialRequestOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options = unserialize(Session::get('auth.login.passkey_authentication_options'), [PublicKeyCredentialRequestOptions::class]));
        $response->assertViewIs('auth.login');
        $response->assertViewHas('options', $options);
    }
}
