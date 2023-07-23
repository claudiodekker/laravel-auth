<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait LoginWithoutRateLimitingTests
{
    /** @test */
    public function password_based_authentication_requests_are_not_rate_limited(): void
    {
        Event::fake(Lockout::class);
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $mock->shouldNotReceive('availableIn');
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertGuest();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function password_based_authentication_requests_do_not_increment_the_rate_limiting_attempts(): void
    {
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $this->expectTimebox();

        $this->submitPasswordBasedLoginAttempt();
    }

    /** @test */
    public function passkey_based_authentication_requests_are_not_rate_limited(): void
    {
        Event::fake(Lockout::class);
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $mock->shouldNotReceive('availableIn');
        $this->expectTimebox();

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

        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The current authentication state is invalid.', $response->exception->getMessage());
        $this->assertGuest();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function passkey_based_authentication_requests_do_not_increment_the_rate_limiting_attempts(): void
    {
        $mock = RateLimiter::partialMock();
        $mock->shouldNotReceive('tooManyAttempts');
        $this->expectTimebox();

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
    }
}
