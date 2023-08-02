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
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

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
        $this->expectTimeboxWithEarlyReturn();

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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
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
        $this->expectTimebox();

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

        $response->assertStatus(428);
        $this->assertSame('The current authentication challenge state is invalid.', $response->exception->getMessage());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(117, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimebox();

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

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertTrue(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(117, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimebox();

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

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertTrue(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimebox();

        $response = $this->postJson(route('login.challenge'), [
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
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimeboxWithEarlyReturn();

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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimeboxWithEarlyReturn();

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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
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
        $this->expectTimeboxWithEarlyReturn();

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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertFalse(Session::has('laravel-auth::public_key_challenge_request_options'));
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
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
        $this->expectTimeboxWithEarlyReturn();

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

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertNotSame($previousId, session()->getId());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(123, CredentialAttributes::fromJson($credential->fresh()->secret)->signCount());
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
    }

    /** @test */
    public function the_public_key_multi_factor_challenge_is_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $this->hitRateLimiter(250, '');

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

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_public_key_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

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

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_public_key_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts_for_one_user_id(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $this->hitRateLimiter(5, 'user_id::'.$user->id);

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

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }
}
