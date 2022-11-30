<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;

trait AccountRecoveryRequestWithoutRateLimitingTests
{
    /** @test */
    public function account_recovery_requests_are_not_rate_limited(): void
    {
        Event::fake(Lockout::class);
        $mock = RateLimiter::spy();

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => 'foo@example.com',
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent'));
        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('availableIn');
        Event::assertNothingDispatched();
    }

    /** @test */
    public function account_recovery_requests_do_not_increment_the_rate_limiting_attempts(): void
    {
        $mock = RateLimiter::spy();

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => 'foo@example.com',
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent'));
        $mock->shouldNotHaveReceived('tooManyAttempts');
        $mock->shouldNotHaveReceived('hit');
    }
}
