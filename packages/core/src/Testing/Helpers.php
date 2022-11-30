<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use App\Models\User;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyWebAuthn;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Mockery\MockInterface;

trait Helpers
{
    protected function predictableRateLimitingKey(Authenticatable $user = null): string
    {
        $username = $user->{$this->usernameField()} ?? $this->defaultUsername();
        $ipAddress = '127.0.0.1';

        return "$username|$ipAddress";
    }

    protected function predictableSudoRateLimitingKey(Authenticatable $user): string
    {
        return $user->getAuthIdentifier().'|127.0.0.1|sudo';
    }

    protected function generateUser($overrides = []): User
    {
        return User::factory()->create(array_merge([
            $this->usernameField() => $this->defaultUsername(),
            'email' => 'claudio@ubient.net',
            'password' => Hash::make('password'),
            'remember_token' => null,
            'has_password' => true,
        ], $overrides));
    }

    protected function submitPasswordBasedRegisterAttempt($overrides = []): TestResponse
    {
        return $this->post(route('register'), array_merge([
            'name' => 'Claudio Dekker',
            'email' => 'claudio@ubient.net',
            $this->usernameField() => $this->defaultUsername(),
            'password' => 'password',
            'password_confirmation' => 'password',
        ], $overrides));
    }

    protected function initializePasskeyBasedRegisterAttempt($overrides = []): TestResponse
    {
        Str::createUuidsUsing(static fn () => 'AUTOMATICALLY-GENERATED-PASSWORD-HASH');

        $response = $this->post(route('register'), array_merge([
            'name' => 'Claudio Dekker',
            'email' => 'claudio@ubient.net',
            $this->usernameField() => $this->defaultUsername(),
            'type' => 'passkey',
        ], $overrides));

        Str::createUuidsUsing();

        return $response;
    }

    protected function submitPasswordBasedLoginAttempt($overrides = []): TestResponse
    {
        return $this->post(route('login'), array_merge([
            $this->usernameField() => $this->defaultUsername(),
            'password' => 'password',
        ], $overrides));
    }

    protected function preAuthenticate($user, $overrides = []): TestResponse
    {
        $this->assertPartlyAuthenticatedAs($response = $this->submitPasswordBasedLoginAttempt($overrides), $user);

        return $response;
    }

    protected function enableSudoMode(): self
    {
        Session::put(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());

        return $this;
    }

    protected function assertFullyAuthenticatedAs(TestResponse $response, $user): void
    {
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(Collection::make(session()->all())->keys()->contains(function ($key) {
            return Str::startsWith($key, 'login_web_');
        }), 'Authenticated session cookie not found.');

        $response->assertSessionMissing('auth.mfa.user_id');
        $response->assertSessionMissing('auth.mfa.remember');
        $response->assertSessionMissing('auth.mfa.throttle_key');
    }

    protected function assertPartlyAuthenticatedAs(TestResponse $response, $user): void
    {
        $this->assertFalse(Collection::make(session()->all())->keys()->contains(function ($key) {
            return Str::startsWith($key, 'login_web_');
        }), 'Authenticated session cookie found.');

        $response->assertSessionHas('auth.mfa.user_id', $user->id);
        $response->assertSessionHas('auth.mfa.throttle_key', $this->predictableRateLimitingKey($user));
    }

    protected function assertHasRememberCookie(TestResponse $response, $user): void
    {
        $this->assertNotNull($user->fresh()->remember_token, 'Remember token not set');
        $this->assertTrue(Collection::make($response->headers->all()['set-cookie'] ?? [])->contains(function ($key) {
            return Str::startsWith($key, 'remember_web_');
        }), 'Remember cookie not found.');
    }

    protected function assertMissingRememberCookie(TestResponse $response, $user): void
    {
        $this->assertNull($user->fresh()->remember_token, 'Remember token was set');
        $this->assertFalse(Collection::make($response->headers->all()['set-cookie'] ?? [])->contains(function ($key) {
            return Str::startsWith($key, 'remember_web_');
        }), 'Remember cookie not found.');
    }

    protected function mockWebauthnChallenge($challenge): void
    {
        $this->partialMock(
            SpomkyWebAuthn::class,
            fn (MockInterface $mock) => $mock->shouldAllowMockingProtectedMethods()->shouldReceive('generateChallenge')->andReturn(base64_decode($challenge, true))
        );
    }

    protected function mockPasskeyCreationOptions(User $user): PublicKeyCredentialCreationOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'spomky-webauthn.herokuapp.com');
        $this->mockWebauthnChallenge('oFUGhUevQHX7J6o4OFau5PbncCATaHwjHDLLzCTpiyw');

        $userEntity = new PublicKeyCredentialUserEntity(
            $user->id,
            $user->{$this->usernameField()},
            $user->name
        );

        return App::make(WebAuthnContract::class)->generatePasskeyCreationOptions($userEntity);
    }

    protected function mockPasskeyRequestOptions(): PublicKeyCredentialRequestOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'authtest.wrp.app');
        $this->mockWebauthnChallenge('R9KnmyTxs6zHJB75bhLKgw');

        return App::make(WebAuthnContract::class)->generatePasskeyRequestOptions();
    }

    protected function mockPublicKeyCreationOptions(User $user, array $excludedCredentials = []): PublicKeyCredentialCreationOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('9WqgpRIYvGMCUYiFT20o1U7hSD193k11zu4tKP7wRcrE26zs1zc4LHyPinvPGS86wu6bDvpwbt8Xp2bQ3VBRSQ');

        $userEntity = new PublicKeyCredentialUserEntity(
            $user->id,
            $user->{$this->usernameField()},
            $user->name
        );

        return App::make(WebAuthnContract::class)->generatePublicKeyCreationOptions($userEntity, new Collection($excludedCredentials));
    }

    protected function mockPublicKeyRequestOptions(array $allowedCredentials): PublicKeyCredentialRequestOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=');

        $options = App::make(WebAuthnContract::class)->generatePublicKeyRequestOptions(
            Collection::make($allowedCredentials)->map(fn ($credential) => CredentialAttributes::fromJson($credential->secret))
        );

        Session::put('laravel-auth::public_key_challenge_request_options', serialize($options));

        return $options;
    }
}
