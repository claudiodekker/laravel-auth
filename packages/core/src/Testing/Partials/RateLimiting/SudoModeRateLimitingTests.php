<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait SudoModeRateLimitingTests
{
    /** @test */
    public function password_based_sudo_mode_confirmation_requests_are_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'password',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function password_based_sudo_mode_confirmation_requests_are_rate_limited_after_too_many_failed_attempts_from_one_account(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        $this->hitRateLimiter(5, 'user_id::1');

        $response = $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'password',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function it_increments_the_rate_limiting_attempts_when_password_based_sudo_mode_confirmation_fails(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts($userKey = 'user_id::1'));
        $this->expectTimebox();

        $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'invalid-password',
        ]);

        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
        $this->assertSame(1, $this->getRateLimitAttempts($userKey));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_password_based_sudo_mode_confirmation_succeeds(): void
    {
        Event::fake([Lockout::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser(['id' => 1]);
        $this->hitRateLimiter(1, $ipKey = 'ip::127.0.0.1');
        $this->hitRateLimiter(1, $userKey = 'user_id::1');
        $this->expectTimeboxWithEarlyReturn();

        $this->actingAs($user)->post(route('auth.sudo_mode'), [
            'password' => 'password',
        ]);

        $this->assertSame(0, $this->getRateLimitAttempts($ipKey));
        $this->assertSame(0, $this->getRateLimitAttempts($userKey));
        Event::assertDispatched(SudoModeEnabled::class);
        Event::assertNotDispatched(Lockout::class);
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
