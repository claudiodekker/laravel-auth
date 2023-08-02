<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\Totp\GoogleTwoFactorAuthenticator;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;

trait SubmitMultiFactorChallengeUsingTotpCodeTests
{
    /** @test */
    public function the_code_field_is_required_when_completing_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->expectTimebox();

        $response = $this->postJson(route('login.challenge'));

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.required', ['attribute' => 'code'])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_code_field_must_be_a_string_when_completing_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->expectTimebox();

        $response = $this->postJson(route('login.challenge'), ['code' => true]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.string', ['attribute' => 'code'])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fully_authenticates_the_user_when_a_valid_time_based_one_time_password_code_is_provided_to_the_multi_factor_challenge(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_fully_authenticates_the_user_when_the_time_based_one_time_password_code_provided_to_the_multi_factor_challenge_is_not_valid_for_one_credential_but_is_for_the_other(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => strrev($secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E')]);
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret]);
        $this->preAuthenticate($user);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_using_a_time_based_one_time_password_when_the_code_does_not_match_any_of_the_users_credentials(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => strrev($secret)]);
        $this->preAuthenticate($user);
        $this->expectTimebox();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::TOTP);
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_using_a_time_based_one_time_password_when_the_current_code_was_already_used_recently(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        Cache::put('auth.mfa.totp_timestamps.'.$user->getAuthIdentifier(), (int) floor(microtime(true) / 30));
        $this->expectTimebox();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(2, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(1, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::TOTP);
    }

    /** @test */
    public function it_sets_the_remember_cookie_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password_with_the_remember_option_set(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user, ['remember' => 'on']);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function it_regenerates_the_session_identifier_to_prevent_session_fixation_attacks_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        $this->expectTimeboxWithEarlyReturn();
        $this->assertNotEmpty($previousId = session()->getId());

        $response = $this->postJson(route('login.challenge'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertNotSame($previousId, session()->getId());
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts('user_id::'.$user->id));
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_is_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->hitRateLimiter(250, '');

        $response = $this->from(route('login.challenge'))->post(route('login.challenge'), ['code' => '123456']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->from(route('login.challenge'))->post(route('login.challenge'), ['code' => '123456']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function the_time_based_one_time_password_multi_factor_challenge_is_rate_limited_after_too_many_failed_attempts_for_one_user_id(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);
        $this->hitRateLimiter(5, 'user_id::'.$user->id);

        $response = $this->from(route('login.challenge'))->post(route('login.challenge'), ['code' => '123456']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Carbon::setTestNow();
    }
}
