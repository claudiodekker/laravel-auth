<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait AccountRecoveryChallengeRateLimitingTests
{
    /** @test */
    public function account_recovery_challenge_requests_are_rate_limited_after_too_many_failed_requests(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        Collection::times(5)->each(fn () => RateLimiter::hit($throttlingKey = 'account-recovery-challenge|127.0.0.1'));

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_provided_email_does_not_resolve_to_an_existing_user(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey = 'account-recovery-challenge|127.0.0.1'));

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => 'nonexistent-user@example.com',
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net']);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', $this->usernameField() => $this->anotherUsername()]);
        $token = Password::getRepository()->create($userA);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey = 'account-recovery-challenge|127.0.0.1'));

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $userB->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_token_does_not_exist(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey = 'account-recovery-challenge|127.0.0.1'));

        $response = $this->post(route('recover-account.challenge', ['token' => 'invalid-token']), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_code_is_not_valid(): void
    {
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey = 'account-recovery-challenge|127.0.0.1'));

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'INV4L-1DCD3',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.recovery')]], $response->exception->errors());
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_resets_the_account_recovery_challenge_rate_limiter_when_recovery_succeeds(): void
    {
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        RateLimiter::hit($throttlingKey = 'account-recovery-challenge|127.0.0.1');
        $this->assertSame(1, RateLimiter::attempts($throttlingKey));

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertRedirect(route('auth.settings'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(0, RateLimiter::attempts($throttlingKey));
        Event::assertNothingDispatched();
    }
}
