<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

trait MultiFactorChallengeWithoutRateLimitingTests
{
    /** @test */
    public function the_public_key_multi_factor_challenge_requests_are_not_rate_limited(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $mock = RateLimiter::spy();

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

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('availableIn');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.challenge.public-key'), $response->exception->getMessage());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_requests_are_not_rate_limited(): void
    {
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $mock = RateLimiter::spy();

        $response = $this->from(route('login.challenge.multi_factor'))->post(route('login.challenge.multi_factor'), ['code' => '123456']);

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('availableIn');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function it_does_not_increment_the_rate_limiter_when_the_public_key_multi_factor_challenge_fails(): void
    {
        $user = $this->generateUser(['id' => 1]);
        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-J4lAqPXhefDrUD7oh5LQMbBH5TE',
            'secret' => '{"id":"J4lAqPXhefDrUD7oh5LQMbBH5TE=","publicKey":"pQECAyYgASFYIGICVDXVg9tymObAz3eI55\/K7TSHz7gEAs0qcEMHkj2fIlggXvAPnA2o\/SFi5rfjR4HvlnUv9XojtHiqtqrvvrfOP2Y=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $this->preAuthenticate($user);
        $this->mockPublicKeyRequestOptions([$credential]);
        $mock = RateLimiter::spy();

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

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('hit');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.challenge.public-key'), $response->exception->getMessage());
    }

    /** @test */
    public function it_does_not_increment_the_rate_limiter_when_the_time_based_one_time_password_multi_factor_challenge_fails(): void
    {
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $mock = RateLimiter::spy();

        $response = $this->from(route('login.challenge.multi_factor'))->post(route('login.challenge.multi_factor'), ['code' => '123456']);

        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('hit');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
    }
}
