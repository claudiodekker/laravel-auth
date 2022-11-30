<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\AuthenticationFailed;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallenged;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait LoginRateLimitingTests
{
    /** @test */
    public function password_based_authentication_requests_are_rate_limited_after_too_many_failed_attempts(): void
    {
        Event::fake([Lockout::class, Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $mock = RateLimiter::partialMock();
        $mock->shouldReceive('tooManyAttempts')->once()->withSomeOfArgs($this->predictableRateLimitingKey())->andReturn(true);
        $mock->shouldReceive('availableIn')->once()->andReturn(75);

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => ['Too many login attempts. Please try again in 75 seconds.']], $response->exception->errors());
        $this->assertGuest();
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
    }

    /** @test */
    public function it_increments_the_rate_limiting_attempts_when_password_based_authentication_fails(): void
    {
        Event::fake([Lockout::class, AuthenticationFailed::class]);
        $this->assertSame(0, RateLimiter::attempts($this->predictableRateLimitingKey()));

        $this->submitPasswordBasedLoginAttempt(['password' => 'invalid']);

        $this->assertSame(1, RateLimiter::attempts($this->predictableRateLimitingKey()));
        Event::assertDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_password_based_authentication_succeeds(): void
    {
        Event::fake([Lockout::class, AuthenticationFailed::class]);
        $user = $this->generateUser();
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_retains_the_rate_limits_when_password_based_authentication_succeeds_partly_due_to_multi_factor_authentication(): void
    {
        Event::fake([Lockout::class, AuthenticationFailed::class, Authenticated::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();
        RateLimiter::hit($throttlingKey = $this->predictableRateLimitingKey());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => route('login.challenge.multi_factor')]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function passkey_based_authentication_requests_are_rate_limited_after_too_many_failed_attempts(): void
    {
        Event::fake([Lockout::class, Authenticated::class, AuthenticationFailed::class]);
        $mock = RateLimiter::partialMock();
        $mock->shouldReceive('tooManyAttempts')->once()->withSomeOfArgs('|127.0.0.1')->andReturn(true);
        $mock->shouldReceive('availableIn')->once()->andReturn(75);

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
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

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => ['Too many login attempts. Please try again in 75 seconds.']], $response->exception->errors());
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
    }

    /** @test */
    public function it_increments_the_rate_limiting_attempts_when_passkey_based_authentication_fails(): void
    {
        Event::fake([Lockout::class, AuthenticationFailed::class]);
        $this->assertSame(0, RateLimiter::attempts('|127.0.0.1'));
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $this->postJson(route('login'), [
            'type' => 'passkey',
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

        $this->assertSame(1, RateLimiter::attempts('|127.0.0.1'));
        Event::assertDispatched(AuthenticationFailed::class);
    }

    /** @test */
    public function it_resets_the_rate_limiting_attempts_when_passkey_based_authentication_succeeds(): void
    {
        Event::fake([Lockout::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        MultiFactorCredential::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));
        RateLimiter::hit($throttlingKey = '|127.0.0.1');
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
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
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey));
        Event::assertNothingDispatched();
    }
}
