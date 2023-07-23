<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;

trait ViewMultiFactorChallengePageTests
{
    /** @test */
    public function the_multi_factor_challenge_page_can_be_viewed(): void
    {
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $response = $this->preAuthenticate($user);
        $response->assertExactJson(['redirect_url' => route('login.challenge')]);
        Config::set('laravel-auth.webauthn.relying_party.id', $rpId = 'configured.rpid');
        Config::set('laravel-auth.webauthn.timeout', $timeout = 12345);
        $this->mockWebauthnChallenge($challenge = 'cPMfYjCIb804eqvknNWAqA');
        $this->expectTimebox();

        $response = $this->get(route('login.challenge'));

        $response->assertOk();
        $this->assertInstanceOf(PublicKeyCredentialRequestOptions::class, $options = unserialize(Session::get('laravel-auth::public_key_challenge_request_options'), [PublicKeyCredentialRequestOptions::class]));
        $this->assertSame([
            'challenge' => $challenge,
            'rpId' => $rpId,
            'timeout' => $timeout,
            'allowCredentials' => [
                [
                    'type' => 'public-key',
                    'id' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
                ],
            ],
            'userVerification' => 'discouraged',
        ], $options->jsonSerialize());
    }

    /** @test */
    public function the_multi_factor_challenge_page_does_not_initialize_a_public_key_challenge_when_the_user_has_no_public_key_credentials(): void
    {
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->forUser($user)->totp()->create();
        $response = $this->preAuthenticate($user);
        $response->assertExactJson(['redirect_url' => route('login.challenge')]);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->get(route('login.challenge'));

        $response->assertOk();
        $response->assertSessionMissing('laravel-auth::public_key_challenge_request_options');
    }

    /** @test */
    public function the_multi_factor_challenge_page_gets_skipped_when_the_user_is_on_the_multi_factor_challenge_step_while_the_last_multi_factor_credential_gets_removed(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->forUser($user)->totp()->create();
        $response = $this->preAuthenticate($user);
        $intendedLocation = session()->get('auth.mfa.intended_location');
        $response->assertExactJson(['redirect_url' => route('login.challenge')]);
        $credential->delete();
        $this->expectTimebox();

        $response = $this->get(route('login.challenge'));

        $response->assertRedirect($intendedLocation);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function the_multi_factor_challenge_page_cannot_be_viewed_when_not_pre_authenticated(): void
    {
        $response = $this->get(route('login.challenge'));

        $response->assertRedirect(route('login'));
        $this->assertGuest();
    }

    /** @test */
    public function the_multi_factor_challenge_page_cannot_be_viewed_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->get(route('login.challenge'));

        $response->assertRedirect(RouteServiceProvider::HOME);
    }
}
