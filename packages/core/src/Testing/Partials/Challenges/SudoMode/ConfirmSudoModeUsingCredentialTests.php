<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode;

use ClaudioDekker\LaravelAuth\Events\SudoModeChallenged;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait ConfirmSudoModeUsingCredentialTests
{
    /** @test */
    public function the_user_can_confirm_sudo_mode_using_a_public_key_credential(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        Redirect::setIntendedUrl($redirectsTo = '/intended');
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => $redirectsTo]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $response->assertSessionMissing('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNotDispatched(SudoModeChallenged::class);
        Event::assertDispatched(SudoModeEnabled::class, fn (SudoModeEnabled $event) => $event->request === request() && $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_confirm_sudo_mode_using_a_malformed_public_key_credential(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
            'credential' => [
                'id' => 'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                'type' => 'public-key',
                'rawId' => 'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPkrrmihjLHmVzzuoMdl2MBAAAAew',
                    'signature' => 'MEUCIEY/vcNkbo/LdMTfLguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=',
                    'userHandle' => null,
                ],
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.public-key')]], $response->exception->errors());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $response->assertSessionHas('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_confirm_sudo_mode_using_a_public_key_credential_that_does_not_exist(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.public-key')]], $response->exception->errors());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $response->assertSessionHas('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_confirm_sudo_mode_using_a_public_key_credential_that_is_not_registered_to_them(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $userA = $this->generateUser(['id' => 1]);
        $userB = $this->generateUser(['id' => 2, $this->usernameField() => $this->anotherUsername()]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($userB)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($userA)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');
        $this->actingAs($userA)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->actingAs($userA)->postJson(route('auth.sudo_mode'), [
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
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $response->assertSessionHas('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function a_passkey_based_user_can_confirm_sudo_mode_using_their_passkey(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        Redirect::setIntendedUrl($redirectsTo = '/intended');
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'authtest.wrp.app');
        $this->mockWebauthnChallenge('R9KnmyTxs6zHJB75bhLKgw');
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => $redirectsTo]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $response->assertSessionMissing('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNotDispatched(SudoModeChallenged::class);
        Event::assertDispatched(SudoModeEnabled::class, fn (SudoModeEnabled $event) => $event->request === request() && $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_use_a_public_key_credential_to_confirm_sudo_mode_when_no_public_key_challenge_was_initialized(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        Redirect::setIntendedUrl('/intended');
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        $this->expectTimebox();

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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

        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The current confirmation state is invalid.', $response->exception->getMessage());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $response->assertSessionMissing('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function it_validates_that_the_credential_is_required_when_an_user_confirms_sudo_mode(): void
    {
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Carbon::setTestNow(now());
        $user = $this->generateUser();
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $this->expectTimebox();

        $response = $this->actingAs($user)
            ->from(route('auth.sudo_mode'))
            ->post(route('auth.sudo_mode'), []);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('validation.required', ['attribute' => 'credential'])]], $response->exception->errors());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $response->assertSessionMissing('laravel-auth::sudo_mode.public_key_challenge_request_options');
        Carbon::setTestNow();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function credential_based_sudo_mode_confirmation_requests_are_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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
        $this->assertSame(['password' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function credential_based_sudo_mode_confirmation_requests_are_rate_limited_after_too_many_failed_attempts_from_one_account(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->hitRateLimiter(5, 'user_id::1');

        $response = $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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
        $this->assertSame(['password' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function it_increments_the_rate_limiting_attempts_when_credential_based_sudo_mode_confirmation_fails(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts($userKey = 'user_id::1'));
        $this->expectTimebox();

        $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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

        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
        $this->assertSame(1, $this->getRateLimitAttempts($userKey));
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_credential_based_sudo_mode_confirmation_succeeds(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
            'secret' => '{"id":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","publicKey":"pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=","signCount":117,"userHandle":"1","transports":[]}',
        ]);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->hitRateLimiter(1, $ipKey = 'ip::127.0.0.1');
        $this->hitRateLimiter(1, $userKey = 'user_id::1');
        $this->expectTimeboxWithEarlyReturn();

        $this->actingAs($user)->postJson(route('auth.sudo_mode'), [
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

        $this->assertSame(0, $this->getRateLimitAttempts($ipKey));
        $this->assertSame(0, $this->getRateLimitAttempts($userKey));
        Event::assertDispatched(SudoModeEnabled::class);
        Event::assertNotDispatched(Lockout::class);
        Carbon::setTestNow();
    }
}
