<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract as Authenticator;
use ClaudioDekker\LaravelAuth\Methods\Totp\GoogleTwoFactorAuthenticator;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait ConfirmTotpCredentialRegistrationTests
{
    /** @test */
    public function it_registers_the_time_based_one_time_password_credential_when_a_valid_confirmation_code_was_provided(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E');

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
            ]);

        $response->assertRedirect(route('auth.settings'));
        $this->assertFalse(Session::has('auth.mfa_setup.pending_totp_secret'));
        $this->assertCount(1, $credentials = LaravelAuth::multiFactorCredentialModel()::all());
        tap($credentials->first(), function (MultiFactorCredential $credential) use ($secret) {
            $this->assertSame(Auth::id(), $credential->user_id);
            $this->assertSame(CredentialType::TOTP, $credential->type);
            $this->assertNotSame($secret, $credential->getRawOriginal('secret'));
            $this->assertSame($credential->secret, $secret);
        });
    }

    /** @test */
    public function the_confirmation_code_is_required_when_registering_a_time_based_one_time_password_credential(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', App::make(Authenticator::class)->generateSecret());

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.required', ['attribute' => 'code'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }

    /** @test */
    public function the_confirmation_code_must_be_a_string_when_registering_a_time_based_one_time_password_credential(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', App::make(Authenticator::class)->generateSecret());

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => 123456,
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.string', ['attribute' => 'code'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }

    /** @test */
    public function the_confirmation_code_must_be_six_characters_when_registering_a_time_based_one_time_password_credential(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', App::make(Authenticator::class)->generateSecret());

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => '12345',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.size.string', ['attribute' => 'code', 'size' => 6])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }

    /** @test */
    public function the_confirmation_code_must_be_valid_for_the_time_based_one_time_password_credential_that_is_being_registered(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_totp_secret', '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E');

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => '123456',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.totp')]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }

    /** @test */
    public function it_fails_to_register_the_time_based_one_time_password_credential_when_none_is_being_registered(): void
    {
        $this->enableSudoMode();
        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => '123456',
            ]);

        $response->assertStatus(428);
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }

    /** @test */
    public function the_user_cannot_register_the_time_based_one_time_password_credential_when_no_longer_in_sudo_mode(): void
    {
        Session::put('auth.mfa_setup.pending_totp_secret', $secret = '4DDDT7XUWA6QPM2ZXHAMPXFEOHSNYN5E');

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_totp.confirm'), [
                'name' => 'Test Authenticator',
                'code' => App::make(GoogleTwoFactorAuthenticator::class)->testCode($secret),
            ]);

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('auth.mfa_setup.pending_totp_secret'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
    }
}
