<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\AccountRecovered;
use ClaudioDekker\LaravelAuth\Events\AccountRecoveryFailed;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait SubmitAccountRecoveryChallengeTests
{
    /** @test */
    public function the_user_account_can_be_recovered(): void
    {
        Carbon::setTestNow(now());
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertFalse($repository->exists($user, $token));
        $this->assertSame(['H4PFK-ENVZV', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P'], $user->fresh()->recovery_codes);
        Event::assertDispatched(AccountRecovered::class, fn ($event) => $event->user->is($user) && $event->request === request());
        Event::assertNotDispatched(AccountRecoveryFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_account_recovery_challenge_code_verification_request_accepts_any_code_when_the_users_recovery_codes_are_cleared(): void
    {
        Carbon::setTestNow(now());
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['recovery_codes' => null]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'INVLD-CODES',
        ]);

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertFalse($repository->exists($user, $token));
        Event::assertDispatched(AccountRecovered::class, fn ($event) => $event->user->is($user) && $event->request === request());
        Event::assertNotDispatched(AccountRecoveryFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_account_cannot_be_recovered_when_authenticated(): void
    {
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net', 'recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', 'recovery_codes' => $codes, $this->usernameField() => $this->anotherUsername()]);
        $repository = Password::getRepository();
        $token = $repository->create($userB);
        $this->assertTrue($repository->exists($userB, $token));

        $response = $this->actingAs($userA)->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $userB->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $this->assertTrue($repository->exists($userB, $token));
        $this->assertSame($codes, $userB->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_account_cannot_be_recovered_when_the_provided_email_does_not_resolve_to_an_existing_user(): void
    {
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => 'nonexistent-user@example.com',
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertTrue($repository->exists($user, $token));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertGuest();
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_account_cannot_be_recovered_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net', 'recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', 'recovery_codes' => $codes, $this->usernameField() => $this->anotherUsername()]);
        $repository = Password::getRepository();
        $token = $repository->create($userA);
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $userB->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertTrue($repository->exists($userA, $token));
        $this->assertSame($codes, $userA->fresh()->recovery_codes);
        $this->assertGuest();
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_account_cannot_be_recovered_when_the_recovery_token_does_not_exist(): void
    {
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => 'invalid-token']), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertTrue($repository->exists($user, $token));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertGuest();
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_account_cannot_be_recovered_when_an_invalid_recovery_code_is_provided(): void
    {
        Event::fake([AccountRecovered::class, AccountRecoveryFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'INV4L-1DCD3',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.recovery')]], $response->exception->errors());
        $this->assertTrue($repository->exists($user, $token));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        $this->assertGuest();
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertDispatched(AccountRecoveryFailed::class, fn ($event) => $event->user->is($user) && $event->request === request());
        Event::assertNotDispatched(AccountRecovered::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
    }

    /** @test */
    public function account_recovery_challenge_requests_are_rate_limited_after_too_many_failed_requests(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

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
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => 'nonexistent-user@example.com',
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net']);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', $this->usernameField() => $this->anotherUsername()]);
        $token = Password::getRepository()->create($userA);
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $userB->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_token_does_not_exist(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => 'invalid-token']), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
    }

    /** @test */
    public function it_increments_the_account_recovery_challenge_rate_limiter_when_the_recovery_code_is_not_valid(): void
    {
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey = 'ip::127.0.0.1'));
        $this->expectTimebox();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'INV4L-1DCD3',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.recovery')]], $response->exception->errors());
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_resets_the_account_recovery_challenge_rate_limiter_when_recovery_succeeds(): void
    {
        Event::fake([Lockout::class]);
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT']]);
        $token = Password::getRepository()->create($user);
        $this->hitRateLimiter(1, '');
        $this->hitRateLimiter(1, $ipKey = 'ip::127.0.0.1');
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts($ipKey));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->post(route('recover-account.challenge', ['token' => $token]), [
            'email' => $user->getEmailForPasswordReset(),
            'code' => 'PIPIM-7LTUT',
        ]);

        $response->assertRedirect(route('auth.settings'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey));
        Event::assertNothingDispatched();
    }
}
