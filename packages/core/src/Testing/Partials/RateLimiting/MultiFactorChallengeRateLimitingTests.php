<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\Totp\GoogleTwoFactorAuthenticator;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

trait MultiFactorChallengeRateLimitingTests
{
    /** @test */
    public function the_public_key_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = MultiFactorCredential::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $mock = RateLimiter::partialMock();
        $mock->shouldReceive('tooManyAttempts')->once()->withSomeOfArgs(session()->get('auth.mfa.throttle_key'))->andReturn(true);
        $mock->shouldReceive('availableIn')->once()->andReturn(75);

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

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 75])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $mock = RateLimiter::partialMock();
        $mock->shouldReceive('tooManyAttempts')->once()->withSomeOfArgs(session()->get('auth.mfa.throttle_key'))->andReturn(true);
        $mock->shouldReceive('availableIn')->once()->andReturn(75);

        $response = $this->from(route('login.challenge.multi_factor'))->post(route('login.challenge.multi_factor'), ['code' => '123456']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 75])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_public_key_multi_factor_challenge_retains_the_rate_limiting_attempts_from_the_login(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        $user = $this->generateUser();
        $credential = MultiFactorCredential::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
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

        $this->assertSame(2, RateLimiter::attempts($throttlingKey));
        $this->assertSame(['credential' => [__('laravel-auth::auth.challenge.public-key')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_retains_the_rate_limiting_attempts_from_the_login(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);

        $response = $this->from(route('login.challenge.multi_factor'))->post(route('login.challenge.multi_factor'), ['code' => '123456']);

        $this->assertSame(2, RateLimiter::attempts($throttlingKey));
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_the_public_key_multi_factor_challenge_succeeds(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        $user = $this->generateUser(['id' => 1]);
        $credential = MultiFactorCredential::factory()->publicKey()->forUser($user)->create([
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

        $this->assertSame(0, RateLimiter::attempts($throttlingKey));
        $this->assertFullyAuthenticatedAs($response, $user);
        Event::assertDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_the_time_based_one_time_password_multi_factor_challenge_succeeds(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);

        $response = $this->from(route('login.challenge.multi_factor'))->post(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey));
        Event::assertDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
    }
}
