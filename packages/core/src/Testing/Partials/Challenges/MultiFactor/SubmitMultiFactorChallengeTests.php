<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Support\Facades\Session;
use Mockery;

trait SubmitMultiFactorChallengeTests
{
    use SubmitMultiFactorChallengeUsingTotpCodeTests;
    use SubmitMultiFactorChallengeUsingPublicKeyCredentialTests;

    /** @test */
    public function it_cannot_complete_a_multi_factor_challenge_when_not_pre_authenticated(): void
    {
        $response = $this->postJson(route('login.challenge'), [
            'credential' => [
                'id' => 'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                'type' => 'public-key',
                'rawId' => 'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew',
                    'signature' => 'MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=',
                    'userHandle' => null,
                ],
            ],
        ]);

        $response->assertRedirect(route('login'));
        $this->assertGuest();
    }

    /** @test */
    public function it_cannot_complete_a_multi_factor_challenge_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->postJson(route('login.challenge'), [
            'credential' => 'foo',
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
    }

    /** @test */
    public function it_clears_any_pending_multi_factor_challenge_details_when_going_back_to_the_login_and_authenticating_again_to_prevent_state_carryover_attacks(): void
    {
        $userA = $this->generateUser(['id' => 1, $this->usernameField() => $this->defaultUsername()]);
        $userB = $this->generateUser(['id' => 2, $this->usernameField() => $this->anotherUsername()]);

        $credentialA = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($userA)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($userB)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);

        // This step emulates the attacker signing in to their account, but not completing the public-key credential challenge.
        // This places the public key challenge request object in the session, which includes all the allowed credentials.
        // (While we're not actually using the endpoints directly, the effect is identical when crafting requests)
        $this->expectTimeboxWithEarlyReturn();
        $this->preAuthenticate($userA, [$this->usernameField() => $userA->{$this->usernameField()}]);
        $this->mockPublicKeyRequestOptions([$credentialA]);
        Mockery::close();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts($userAKey = 'username::'.$userA->{$this->usernameField()}));
        $this->assertSame(0, $this->getRateLimitAttempts($userBKey = 'username::'.$userB->{$this->usernameField()}));

        // Next, instead of completing the challenge, the attacker will take their session id / CSRF tokens etc., and crafts
        // a manual 'login' attempt to that signs in the victim, which returns a redirect to the victim's MFA challenge.
        $this->expectTimeboxWithEarlyReturn();
        $craftedLogin = $this->preAuthenticate($userB, [$this->usernameField() => $userB->{$this->usernameField()}]);
        $craftedLogin->assertExactJson(['redirect_url' => route('login.challenge')]);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts($ipKey));
        $this->assertSame(1, $this->getRateLimitAttempts($userAKey));
        $this->assertSame(1, $this->getRateLimitAttempts($userBKey));

        // However, since we haven't actually followed the redirect, this user's MFA challenge options haven't been initialized yet.
        // The result is a state in which the victim is being authenticated, with the attacker's MFA challenge details still set.
        // At this point all the attacker has to do, is to confirm their own MFA challenge, to be signed in as the victim.
        // To prevent this, we'll make sure to always clear any MFA challenge details during the initial login attempt.
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
    }
}
