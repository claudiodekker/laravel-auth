<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;

trait AccountRecoveryRequestRateLimitingTests
{
    /** @test */
    public function account_recovery_requests_are_rate_limited_after_too_many_requests(): void
    {
        Carbon::setTestNow(now());
        Notification::fake();
        Event::fake([Lockout::class]);
        Collection::times(5)->each(fn () => RateLimiter::hit('account-recovery|127.0.0.1'));

        $response = $this->post(route('recover-account'), [
            'email' => 'foo@example.com',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('laravel-auth::auth.recovery.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Notification::assertNothingSent();
        Carbon::setTestNow();
    }

    /** @test */
    public function it_increments_the_rate_limiter_when_an_account_recovery_request_is_made(): void
    {
        $this->assertSame(0, RateLimiter::attempts('account-recovery|127.0.0.1'));

        $this->post(route('recover-account'), [
            'email' => 'foo@example.com',
        ]);

        $this->assertSame(1, RateLimiter::attempts('account-recovery|127.0.0.1'));
    }
}
