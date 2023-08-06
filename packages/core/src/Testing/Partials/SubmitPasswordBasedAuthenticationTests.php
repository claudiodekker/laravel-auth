<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\AuthenticationFailed;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallenged;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Validation\ValidationException;

trait SubmitPasswordBasedAuthenticationTests
{
    /** @test */
    public function it_authenticates_the_user_using_an_username_and_password(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser();
        $this->expectTimeboxWithEarlyReturn();
        $this->hitRateLimiter(1, '');
        $this->hitRateLimiter(1, $userKey = 'username::'.$this->defaultUsername());
        $this->hitRateLimiter(1, $ipKey = 'ip::127.0.0.1');

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts($userKey));
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey));
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function it_cannot_perform_password_based_authentication_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->submitPasswordBasedLoginAttempt([$this->usernameField() => 'should-not-cause-a-validation-error']);

        $response->assertRedirect(RouteServiceProvider::HOME);
    }

    /** @test */
    public function it_validates_that_the_username_is_required_during_password_based_authentication(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt([$this->usernameField() => '']);

        $this->assertUsernameRequiredValidationError($response);
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_username_is_a_string_during_password_based_authentication(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt([$this->usernameField() => UploadedFile::fake()->image('username.jpg')]);

        $this->assertUsernameMustBeAStringValidationError($response);
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_username_is_valid_during_password_based_authentication(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt([$this->usernameField() => $this->invalidUsername()]);

        $this->assertUsernameMustBeValidValidationError($response);
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->invalidUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_is_required_during_password_based_authentication(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt(['password' => '']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.required', ['attribute' => 'password'])]], $response->exception->errors());
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_is_a_string_during_password_based_authentication(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt(['password' => 123]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.string', ['attribute' => 'password'])]], $response->exception->errors());
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_fails_to_authenticate_when_an_invalid_password_was_provided(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->generateUser();
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt(['password' => 'invalid']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === $this->defaultUsername());
    }

    /** @test */
    public function it_fails_to_authenticate_when_invalid_credentials_were_provided_during_password_based_authentication(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->generateUser();
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt([
            $this->usernameField() => $this->nonExistentUsername(),
            'password' => 'invalid',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->nonExistentUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === $this->nonExistentUsername());
    }

    /** @test */
    public function it_fails_to_authenticate_when_a_passwordless_user_attempts_to_authenticate_using_a_password(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->generateUser(['has_password' => false]);
        $this->expectTimebox();

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === $this->defaultUsername());
    }

    /** @test */
    public function it_sets_the_remember_cookie_when_the_user_authenticates_using_an_username_and_password_with_the_remember_option_enabled(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser();
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedLoginAttempt(['remember' => 'on']);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_sends_the_user_to_their_intended_location_when_authenticated_using_an_username_and_password(): void
    {
        Redirect::setIntendedUrl($redirectsTo = '/intended');

        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser();
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => $redirectsTo]);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertFullyAuthenticatedAs($response, $user);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_authenticated_using_an_username_and_password(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class, SudoModeEnabled::class]);
        $user = $this->generateUser();
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertFullyAuthenticatedAs($response, $user);
        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function the_session_identifier_gets_regenerated_to_prevent_session_fixation_attacks_when_username_and_password_based_authentication_succeeds(): void
    {
        $user = $this->generateUser();
        $this->assertNotEmpty($previousId = session()->getId());
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertNotSame($previousId, session()->getId());
    }

    /** @test */
    public function it_sends_a_multi_factor_authentication_challenge_when_the_user_authenticates_using_an_username_and_password_and_a_multi_factor_credential_exists_for_the_user(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class, SudoModeEnabled::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedLoginAttempt();

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => route('login.challenge')]);
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $response->assertSessionHas('auth.mfa.remember', false);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('username::'.$this->defaultUsername()));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(MultiFactorChallenged::class, fn (MultiFactorChallenged $event) => $event->user->is($user));
    }

    /** @test */
    public function password_based_authentication_requests_are_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->hitRateLimiter(250, '');

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertGuest();
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function password_based_authentication_requests_are_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertGuest();
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
    }

    /** @test */
    public function password_based_authentication_requests_are_rate_limited_after_too_many_failed_attempts_for_one_username(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->hitRateLimiter(5, 'username::'.$this->defaultUsername());

        $responseA = $this->submitPasswordBasedLoginAttempt();

        $this->assertInstanceOf(ValidationException::class, $responseA->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $responseA->exception->errors());
        $this->assertGuest();
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);

        $this->expectTimebox();

        $responseB = $this->submitPasswordBasedLoginAttempt([$this->usernameField() => $this->nonExistentUsername()]);
        $this->assertInstanceOf(ValidationException::class, $responseB->exception);
        $this->assertSame([$this->usernameField() => ['These credentials do not match our records.']], $responseB->exception->errors());
        Carbon::setTestNow();
    }
}
