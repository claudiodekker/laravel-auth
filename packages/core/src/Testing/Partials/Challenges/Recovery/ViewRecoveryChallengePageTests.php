<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\AccountRecoveryFailed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait ViewRecoveryChallengePageTests
{
    /** @test */
    public function the_account_recovery_challenge_page_can_be_viewed(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $token = Password::getRepository()->create($user);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $user->{$this->usernameField()},
        ]));

        $response->assertOk();
    }

    /** @test */
    public function the_account_recovery_challenge_page_is_skipped_when_the_user_does_not_have_any_recovery_codes(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, AccountRecoveryFailed::class]);
        $user = $this->generateUser(['recovery_codes' => null]);
        $repository = Password::getRepository();
        $token = $repository->create($user);
        $this->assertTrue($repository->exists($user, $token));
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $username = $user->{$this->usernameField()},
        ]));

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
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_authenticated(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);

        $response = $this->actingAs($user)
            ->get(route('recover-account.challenge', ['token' => 'foo']));

        $response->assertRedirect(RouteServiceProvider::HOME);
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_provided_username_does_not_resolve_to_an_existing_user(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $token = Password::getRepository()->create($user);
        $this->expectTimebox();

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $this->nonExistentUsername(),
        ]));

        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net', 'recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', $this->usernameField() => $this->anotherUsername(), 'recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $token = Password::getRepository()->create($userA);
        $this->expectTimebox();

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $userB->{$this->usernameField()},
        ]));

        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_does_not_exist(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $this->expectTimebox();

        $response = $this->get(route('recover-account.challenge', [
            'token' => 'invalid-token',
            $this->usernameField() => $user->{$this->usernameField()},
        ]));

        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_has_expired(): void
    {
        Carbon::setTestNow(now());
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $token = Password::getRepository()->create($user);
        Carbon::setTestNow(now()->addHour()->addSecond());
        $this->expectTimebox();

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $user->{$this->usernameField()},
        ]));

        $response->assertForbidden();
        $response->assertSessionMissing('auth.recovery_mode.user_id');
        $response->assertSessionMissing('auth.recovery_mode.enabled_at');
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame(__('laravel-auth::auth.recovery.invalid', ['field' => $this->usernameField()]), $response->exception->getMessage());
        Carbon::setTestNow();
    }
}
