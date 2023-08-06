<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\AccountRecoveryFailed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait SubmitRecoveryChallengeTests
{
    /** @test */
    public function the_user_can_begin_to_recover_the_account(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username = $user->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertGuest();
        $response->assertRedirect(route('recover-account.reset'));
        $response->assertSessionHas('auth.recovery_mode.user_id', $user->id);
        $response->assertSessionHas('auth.recovery_mode.enabled_at', now());
        $this->assertFalse($repository->exists($user, $token));
        $this->assertSame(['H4PFK-ENVZV', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P'], $user->fresh()->recovery_codes);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$username));
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function the_account_recovery_challenge_code_verification_request_accepts_any_code_when_the_users_recovery_codes_have_been_cleared(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => null]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username = $user->{$this->usernameField()},
            'code' => 'INVLD-CODES',
        ]);

        $this->assertGuest();
        $response->assertRedirect(route('recover-account.reset'));
        $response->assertSessionHas('auth.recovery_mode.user_id', $user->id);
        $response->assertSessionHas('auth.recovery_mode.enabled_at', now());
        $this->assertFalse($repository->exists($user, $token));
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$username));
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_begin_to_recover_the_account_when_already_authenticated(): void
    {
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net', 'recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', 'recovery_codes' => $codes, $this->usernameField() => $this->anotherUsername()]);
        $repository = Password::getRepository();
        $token = $repository->create($userB);
        $this->assertTrue($repository->exists($userB, $token));

        $response = $this->actingAs($userA)->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $userB->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertAuthenticatedAs($userA);
        $this->assertTrue($repository->exists($userB, $token));
        $this->assertSame($codes, $userB->fresh()->recovery_codes);
    }

    /** @test */
    public function the_user_cannot_begin_to_recover_the_account_when_the_provided_username_does_not_resolve_to_an_existing_user(): void
    {
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username = $this->nonExistentUsername(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertGuest();
        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
        $this->assertTrue($repository->exists($user, $token));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$username));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_begin_to_recover_the_account_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net', 'recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', 'recovery_codes' => $codes, $this->usernameField() => $this->anotherUsername()]);
        $repository = Password::getRepository();
        $token = $repository->create($userA);
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username = $userB->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertGuest();
        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
        $this->assertTrue($repository->exists($userA, $token));
        $this->assertSame($codes, $userA->fresh()->recovery_codes);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$username));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_begin_to_recover_the_account_when_the_recovery_token_does_not_exist(): void
    {
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => 'invalid-token']), [
            $this->usernameField() => $username = $user->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertGuest();
        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$username));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_begin_to_recover_the_account_when_an_invalid_recovery_code_is_provided(): void
    {
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username = $user->{$this->usernameField()},
            'code' => 'INV4L-1DCD3',
        ]);

        $this->assertGuest();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.recovery')]], $response->exception->errors());
        $this->assertTrue($repository->exists($user, $token));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$username));
        Event::assertDispatched(AccountRecoveryFailed::class, fn (AccountRecoveryFailed $event) => $event->user->is($user));
        Event::assertNotDispatched(Lockout::class);
    }

    /** @test */
    public function account_recovery_challenge_requests_are_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->hitRateLimiter(250, '');

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $user->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertTrue($repository->exists($user, $token));
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function account_recovery_challenge_requests_are_rate_limited_after_too_many_failed_requests_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $user->{$this->usernameField()},
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertTrue($repository->exists($user, $token));
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }

    /** @test */
    public function account_recovery_challenge_requests_are_rate_limited_after_too_many_failed_requests_for_one_username(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $username = $user->{$this->usernameField()};
        $this->hitRateLimiter(5, 'username::'.$username);

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            $this->usernameField() => $username,
            'code' => 'PIPIM-7LTUT',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertTrue($repository->exists($user, $token));
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Carbon::setTestNow();
    }
}
