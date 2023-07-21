<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyWebAuthn;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use ClaudioDekker\LaravelAuth\Testing\Support\InstantlyResolvingTimebox;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;
use Illuminate\Testing\TestResponse;
use Mockery\MockInterface;

trait Helpers
{
    protected function hitRateLimiter(int $times, string $key): void
    {
        foreach (range(1, $times) as $i) {
            RateLimiter::hit("auth::$key");
        }
    }

    protected function getRateLimitAttempts($key): int
    {
        return RateLimiter::attempts("auth::$key");
    }

    protected function generateUser($overrides = []): Model&Authenticatable
    {
        return LaravelAuth::userModel()::factory()->create(array_merge([
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

    protected function preAuthenticate(Authenticatable $user, $overrides = []): TestResponse
    {
        $this->assertPartlyAuthenticatedAs($response = $this->submitPasswordBasedLoginAttempt($overrides), $user);

        return $response;
    }

    protected function enableSudoMode(): self
    {
        Session::put(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());

        return $this;
    }

    protected function assertFullyAuthenticatedAs(TestResponse $response, Authenticatable $user): void
    {
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(Collection::make(session()->all())->keys()->contains(function ($key) {
            return Str::startsWith($key, 'login_web_');
        }), 'Authenticated session cookie not found.');

        $response->assertSessionMissing('auth.mfa.user_id');
        $response->assertSessionMissing('auth.mfa.remember');
    }

    protected function assertPartlyAuthenticatedAs(TestResponse $response, Authenticatable $user): void
    {
        $this->assertFalse(Collection::make(session()->all())->keys()->contains(function ($key) {
            return Str::startsWith($key, 'login_web_');
        }), 'Authenticated session cookie found.');

        $response->assertSessionHas('auth.mfa.user_id', $user->id);
    }

    protected function assertHasRememberCookie(TestResponse $response, Authenticatable $user): void
    {
        $this->assertNotNull($user->fresh()->remember_token, 'Remember token not set');
        $this->assertTrue(Collection::make($response->headers->all()['set-cookie'] ?? [])->contains(function ($key) {
            return Str::startsWith($key, 'remember_web_');
        }), 'Remember cookie not found.');
    }

    protected function assertMissingRememberCookie(TestResponse $response, Authenticatable $user): void
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

    protected function mockPasskeyCreationOptions(Authenticatable $user): PublicKeyCredentialCreationOptions
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

    protected function mockPasskeyCreationOptionsTwo(Authenticatable $user): PublicKeyCredentialCreationOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('ImJ9UcKWlxQeb8V4MxSrrg');

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

    protected function mockPasskeyRequestOptionsTwo(): PublicKeyCredentialRequestOptions
    {
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        $this->mockWebauthnChallenge('ImJ9UcKWlxQeb8V4MxSrrg');

        return App::make(WebAuthnContract::class)->generatePasskeyRequestOptions();
    }

    protected function mockPublicKeyCreationOptions(Authenticatable $user, array $excludedCredentials = []): PublicKeyCredentialCreationOptions
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

    protected function submitPasskeyBasedRegisterAttempt(): TestResponse
    {
        return $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve',
                'rawId' => 'AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJvRlVHaFVldlFIWDdKNm80T0ZhdTVQYm5jQ0FUYUh3akhETEx6Q1RwaXl3Iiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ',
                    'attestationObject' => 'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgAMCQZYRl2cA+ab2MB3OGBCbq3j62rSubwhaCVSHJvKMCIQD0mMLs/5jjwd0KxYzb9/iM15T1gJ3L1Uv5BnMtQtVYBmhhdXRoRGF0YVjStIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXE8bBwAAAAAAAAAAAAAAAAAAAAAATgBZM8GsVbglM+KhT2jQIJ2IKGSik7bxiAGiAEgG55RxsvFJLXSP4zdAnraSJIsPfvkdABfWujiZxw/huGiFrq/j8Y/rCPcQxPgFXkCr3qUBAgMmIAEhWCBOSwRVQxXPb76nvmQ2HQ8i5Bin8M4zfZCqIlKXrcxxmyJYIOFCAZ9+rRhklvn1nk2TahaCvpH96emEuKoGxpEObvQg',
                ],
                'type' => 'public-key',
            ],
        ]);
    }

    protected function submitRegisterPublicKeyCredentialAttempt()
    {
        return $this->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
            'credential' => $this->publicKeyCredential(),
        ]);
    }

    protected function publicKeyCredential()
    {
        return [
            'id' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
            'rawId' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK',
            'response' => [
                'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
                'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ',
            ],
            'type' => 'public-key',
        ];
    }

    protected function useInstantlyResolvingTimebox()
    {
        App::bind(Timebox::class, fn () => new InstantlyResolvingTimebox());
    }

    protected function expectTimebox(): void
    {
        $this->partialMock(Timebox::class, function (MockInterface $timebox) {
            $timebox->shouldReceive('call')->once()->andReturnUsing(function ($callback) use ($timebox) {
                return $callback($timebox->shouldReceive('returnEarly')->never()->getMock());
            });
        });
    }

    protected function expectTimeboxWithEarlyReturn(): void
    {
        $this->partialMock(Timebox::class, function (MockInterface $timebox) {
            $timebox->shouldReceive('call')->once()->andReturnUsing(function ($callback) use ($timebox) {
                return $callback($timebox->shouldReceive('returnEarly')->once()->getMock());
            });
        });
    }
}
