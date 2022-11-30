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
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'));

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => ['The code field is required.']], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
    }

    /** @test */
    public function the_code_field_must_be_a_string_when_completing_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), ['code' => true]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => ['The code must be a string.']], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fully_authenticates_the_user_when_a_valid_time_based_one_time_password_code_is_provided_to_the_multi_factor_challenge(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_fully_authenticates_the_user_when_the_time_based_one_time_password_code_provided_to_the_multi_factor_challenge_is_not_valid_for_one_credential_but_is_for_the_other(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => strrev($secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E')]);
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret]);
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_using_a_time_based_one_time_password_when_the_code_does_not_match_any_of_the_users_credentials(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => strrev($secret)]);
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::TOTP);
    }

    /** @test */
    public function it_fails_the_multi_factor_challenge_using_a_time_based_one_time_password_when_the_current_code_was_already_used_recently(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        Cache::put('auth.mfa.totp_timestamps.'.$user->getAuthIdentifier(), (int) floor(microtime(true) / 30));

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertPartlyAuthenticatedAs($response, $user);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertDispatched(MultiFactorChallengeFailed::class, fn (MultiFactorChallengeFailed $event) => $event->user->is($user) && $event->type === CredentialType::TOTP);
    }

    /** @test */
    public function it_sets_the_remember_cookie_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password_with_the_remember_option_set(): void
    {
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user, ['remember' => 'on']);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Authenticated::class, MultiFactorChallengeFailed::class, SudoModeEnabled::class]);
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertFullyAuthenticatedAs($response, $user);
        Event::assertNotDispatched(MultiFactorChallengeFailed::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function it_regenerates_the_session_identifier_to_prevent_session_fixation_attacks_when_the_user_completes_the_multi_factor_challenge_using_a_time_based_one_time_password(): void
    {
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create(['secret' => $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E']);
        $this->preAuthenticate($user);
        $this->assertNotEmpty($previousId = session()->getId());

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
        ]);

        $response->assertStatus(200);
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertNotSame($previousId, session()->getId());
        $this->assertFullyAuthenticatedAs($response, $user);
    }
}
