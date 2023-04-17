<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;

trait MultiFactorChallengeViewTests
{
    /** @test */
    public function the_multi_factor_challenge_page_uses_blade_views(): void
    {
        Redirect::setIntendedUrl($redirectsTo = '/intended');
        $this->assertSame($redirectsTo, Session::get('url.intended'));
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->assertNull(Session::get('url.intended'));

        $response = $this->get(route('login.challenge.multi_factor'));

        /** @var PublicKeyCredentialRequestOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options = unserialize(Session::get('laravel-auth::public_key_challenge_request_options'), [PublicKeyCredentialRequestOptions::class]));

        $response->assertViewIs('auth.challenges.multi_factor');
        $response->assertViewHas('availableMethods');
        $response->assertViewHas('intendedLocation', $redirectsTo);
        $response->assertViewHas('options', $options);
        $this->assertCount(2, $response->viewData('availableMethods'));
        $this->assertSame(CredentialType::PUBLIC_KEY, $response->viewData('availableMethods')[0]);
        $this->assertSame(CredentialType::TOTP, $response->viewData('availableMethods')[1]);
    }
}
