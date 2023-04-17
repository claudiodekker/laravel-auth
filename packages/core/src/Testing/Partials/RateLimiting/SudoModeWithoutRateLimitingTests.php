<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Session;

trait SudoModeWithoutRateLimitingTests
{
    /** @test */
    public function password_based_sudo_mode_confirmation_requests_are_not_rate_limited(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $mock->shouldNotReceive('availableIn');

        $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'invalid-password',
        ]);

        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_does_not_increment_the_rate_limiting_attempts_when_password_based_sudo_mode_confirmation_fails(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();
        $mock = RateLimiter::spy();

        $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'invalid-password',
        ]);

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('hit');
        Event::assertNothingDispatched();
    }

    /** @test */
    public function credential_based_sudo_mode_confirmation_requests_are_not_rate_limited(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $mock->shouldNotReceive('availableIn');

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

        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_does_not_increment_the_rate_limiting_attempts_when_credential_based_sudo_mode_confirmation_fails(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->actingAs($user)->get(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $mock = RateLimiter::spy();

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

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('hit');
        Event::assertNothingDispatched();
    }
}
