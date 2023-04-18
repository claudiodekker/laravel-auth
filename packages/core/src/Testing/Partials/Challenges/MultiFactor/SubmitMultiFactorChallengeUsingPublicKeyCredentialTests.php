<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;

trait SubmitMultiFactorChallengeUsingPublicKeyCredentialTests
{
    /** @test */
    public function it_fully_authenticates_the_user_when_a_valid_public_key_credential_signature_is_provided_to_the_multi_factor_challenge(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_using_a_public_key_credential_when_no_public_key_challenge_was_initialized(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(428);
        $this->assertSame('The current authentication challenge state is invalid.', $response->exception->getMessage());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(117, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_when_the_provided_public_key_credential_signature_does_not_match_any_of_the_users_credentials(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertTrue(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(117, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::PUBLIC_KEY);
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_when_the_provided_public_key_credential_signature_is_valid_but_has_a_signature_counter_mismatch(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":123,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertTrue(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::PUBLIC_KEY);
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_when_the_provided_public_key_credential_signature_is_malformed(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'credential' => [
                'id' => 'eHouz_Zi7-BmByHjJ_tZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                'type' => 'public-key',
                'rawId' => 'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgdPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPkrrmihjLHmVzzuoMdl2MBAAAAew==',
                    'signature' => 'MEUCIEY/vcNkbo/LdMTfLguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=',
                    'userHandle' => null,
                ],
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertTrue(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(117, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::PUBLIC_KEY);
        Event::assertNotDispatched(Authenticated::class);
    }

    /** @test */
    public function it_sets_the_remember_cookie_when_the_user_completes_the_multi_factor_challenge_using_a_public_key_credential_with_the_remember_option_set(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user, ['remember' => 'on']);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_the_user_completes_the_multi_factor_challenge_using_a_public_key_credential(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function it_increments_the_signature_counter_when_the_user_completes_the_multi_factor_challenge_using_a_public_key_credential(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
    }

    /** @test */
    public function it_regenerates_the_session_identifier_to_prevent_session_fixation_attacks_when_the_user_completes_the_multi_factor_challenge_using_a_public_key_credential(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->assertNotEmpty($previousId = session()->getId());
        $this->mockPublicKeyRequestOptions([$credential]);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertNotSame($previousId, session()->getId());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
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
        $this->preAuthenticate($userA, [$this->usernameField() => $userA->{$this->usernameField()}]);
        $this->mockPublicKeyRequestOptions([$credentialA]);

        // Next, instead of completing the challenge, the attacker will take their session id / CSRF tokens etc., and crafts
        // a manual 'login' attempt to that signs in the victim, which returns a redirect to the victim's MFA challenge.
        $craftedLogin = $this->preAuthenticate($userB, [$this->usernameField() => $userB->{$this->usernameField()}]);
        $craftedLogin->assertExactJson(['redirect_url' => route('login.challenge.multi_factor')]);

        // However, since we haven't actually followed the redirect, this user's MFA challenge options haven't been initialized yet.
        // The result is a state in which the victim is being authenticated, with the attacker's MFA challenge details still set.
        // At this point all the attacker has to do, is to confirm their own MFA challenge, to be signed in as the victim.
        // To prevent this, we'll make sure to always clear any MFA challenge details during the initial login attempt.
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
    }
}
