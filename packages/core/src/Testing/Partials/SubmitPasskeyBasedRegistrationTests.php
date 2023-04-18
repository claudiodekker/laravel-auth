<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;
use ParagonIE\ConstantTime\Base64UrlSafe;

trait SubmitPasskeyBasedRegistrationTests
{
    /** @test */
    public function it_claims_the_user_when_initializing_passkey_based_registration(): void
    {
        Event::fake(Registered::class);
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        Config::set('laravel-auth.webauthn.relying_party.name', 'Laravel Auth Package');
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $response = $this->initializePasskeyBasedRegisterAttempt();

        $this->assertGuest();
        $user = tap(LaravelAuth::userModel()::firstOrFail(), function ($user) {
            $this->assertSame('Claudio Dekker', $user->name);
            $this->assertSame($this->defaultUsername(), $user->{$this->usernameField()});
            $this->assertTrue(password_verify('AUTOMATICALLY-GENERATED-PASSWORD-HASH', $user->password));
            $this->assertFalse($user->has_password);
        });
        /** @var PublicKeyCredentialCreationOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options = unserialize(Session::get('auth.register.passkey_creation_options'), [PublicKeyCredentialCreationOptions::class]));
        $this->assertEquals($expectedJson = [
            'rp' => [
                'id' => 'localhost',
                'name' => 'Laravel Auth Package',
            ],
            'user' => [
                'id' => Base64UrlSafe::encodeUnpadded($user->getAuthIdentifier()),
                'name' => $this->defaultUsername(),
                'displayName' => $user->name,
            ],
            'challenge' => $options->challenge(),
            'pubKeyCredParams' => [
                [
                    'type' => 'public-key',
                    'alg' => -7,
                ], [
                    'type' => 'public-key',
                    'alg' => -257,
                ],
            ],
            'timeout' => 30000,
            'attestation' => 'none',
            'authenticatorSelection' => [
                'authenticatorAttachment' => 'platform',
                'requireResidentKey' => true,
                'residentKey' => 'required',
                'userVerification' => 'required',
            ],
        ], $options->jsonSerialize());
        $response->assertOk();
        $response->assertExactJson($expectedJson);
        Event::assertNotDispatched(Registered::class);
    }

    /** @test */
    public function it_cannot_initialize_passkey_based_registration_when_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->initializePasskeyBasedRegisterAttempt();

        $response->assertRedirect(RouteServiceProvider::HOME);
        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertCount(1, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_name_is_required_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['name' => '']);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.required', ['attribute' => 'name'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_name_is_a_string_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['name' => 123]);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.string', ['attribute' => 'name'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_name_does_not_exceed_255_characters_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['name' => str_repeat('a', 256)]);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.max.string', ['attribute' => 'name', 'max' => 255])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_username_is_required_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt([$this->usernameField() => '']);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertUsernameRequiredValidationError($response);
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_username_does_not_exceed_255_characters_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt([$this->usernameField() => $this->tooLongUsername()]);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertUsernameTooLongValidationError($response);
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_email_is_required_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['email' => '']);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.required', ['attribute' => 'email'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_email_does_not_exceed_255_characters_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['email' => str_repeat('a', 256).'@example.com']);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.max.string', ['attribute' => 'email', 'max' => 255])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_email_is_valid_when_initializing_passkey_based_registration(): void
    {
        $response = $this->initializePasskeyBasedRegisterAttempt(['email' => 'foo']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.email', ['attribute' => 'email'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_user_does_not_already_exist_when_initializing_passkey_based_registration(): void
    {
        $this->generateUser([$this->usernameField() => $this->defaultUsername()]);

        $response = $this->initializePasskeyBasedRegisterAttempt([$this->usernameField() => $this->defaultUsername()]);

        $response->assertSessionMissing('auth.register.passkey_creation_options');
        $this->assertUsernameAlreadyExistsValidationError($response);
        $this->assertCount(1, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_confirms_passkey_based_registration(): void
    {
        Event::fake(Registered::class);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
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

        $response->assertCreated();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertAuthenticatedAs($user);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(1, $credentials = LaravelAuth::multiFactorCredentialModel()::all());
        tap($credentials->first(), function (MultiFactorCredential $key) use ($user) {
            $this->assertSame('public-key-AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve', $key->id);
            $this->assertSame($user->id, $key->user_id);
            $this->assertEquals(CredentialType::PUBLIC_KEY, $key->type);
            $this->assertEquals('User Passkey', $key->name);
            $this->assertSame('{"id":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI\/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve","publicKey":"pQECAyYgASFYIE5LBFVDFc9vvqe+ZDYdDyLkGKfwzjN9kKoiUpetzHGbIlgg4UIBn36tGGSW+fWeTZNqFoK+kf3p6YS4qgbGkQ5u9CA=","signCount":1548688135,"userHandle":"1","transports":[]}', $key->secret);
        });
        Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->is($user));
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_when_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->postJson(route('register'), [
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

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertCount(1, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_when_no_options_were_initialized(): void
    {
        Event::fake(Registered::class);
        $response = $this->postJson(route('register'), [
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

        $response->assertStatus(428);
        $this->assertGuest();
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_using_a_credential_that_is_malformed(): void
    {
        Event::fake(Registered::class);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'name' => 'Malformed Credential',
                'credential' => [
                    'id' => 'AFkzwaxVuCUz4qFPaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve',
                    'rawId' => 'AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI/jN0Cetp9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve',
                    'response' => [
                        'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJlFIWDdKNm80T0ZhdTVQYm5jQ0Fx6Q1RwaXl3Iiwib3JpZ2luIjoiaHR0cHM6Ly9zcG9ta3ktd2ViYXV0aG4uaGVyb2t1YXBwLmNvbSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ==',
                        'attestationObject' => 'o2NmbXRmcGFja2VkZ2F0dFN0bXS2FsZyZjc2lnWEcwRQIgAMCQZYRl2cA+ab2MB3OGBCbq3j62rSubwhaCVSHJvKMCIQD0mMLs/5jjwd0KxYzb9/iM15TIXbbgSILsWHHbR0Fjkl96X4ROZYLvVtOopBWCQoAqpFXE8bBwAAAAAAAAAAAAAAAAAAAAAATgBZM8GsVbglM+KhT2jQIJ2IKGSik7bxiAGiAEgG55RxsvFJLXSP4zdAnraSJIsPfvxw/huGiFrq/j8Y/rCPcQxPgFXkCr3qUBAgMmIAEhWCBOSwRVQxXPb76nvmQ2HQ8i5Bin8M4zfZCqIlKXrcxxmyJYIOFCAZ9+rRhklvn1nk2TahaCvpH96emEuKoGxpEObvQg',
                    ],
                    'type' => 'public-key',
                ],
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => ['The credential field is invalid.']]);
        $this->assertGuest();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_when_the_challenge_does_not_match(): void
    {
        Event::fake(Registered::class);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
                'rawId' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVN2hTRDE5M2sxMXp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => ['The credential field is invalid.']]);
        $this->assertGuest();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_confirms_passkey_based_registration_on_an_insecure_origin_that_has_been_manually_marked_as_trustworthy(): void
    {
        Event::fake(Registered::class);
        Config::set('app.debug', true);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['localhost']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptionsTwo($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCA_whW46e5nw7iOM8BHvuPf4NfvpQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR_D-Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertCreated();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertAuthenticatedAs($user);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(1, $credentials = LaravelAuth::multiFactorCredentialModel()::all());
        tap($credentials->first(), function (MultiFactorCredential $key) use ($user) {
            $this->assertSame('public-key-ID_CFbjp7mfDuI4zwEe-49_g1-8', $key->id);
            $this->assertSame($user->id, $key->user_id);
            $this->assertEquals(CredentialType::PUBLIC_KEY, $key->type);
            $this->assertEquals('User Passkey', $key->name);
            $this->assertSame('{"id":"ID\/CFbjp7mfDuI4zwEe+49\/g1+8=","publicKey":"pQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR\/D+Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4=","signCount":0,"userHandle":"1","transports":[]}', $key->secret);
        });
        Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->is($user));
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_on_an_insecure_origin_that_has_been_manually_marked_as_trustworthy_when_debug_is_disabled(): void
    {
        Event::fake(Registered::class);
        Config::set('app.debug', false);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['localhost']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptionsTwo($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCA_whW46e5nw7iOM8BHvuPf4NfvpQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR_D-Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => ['The credential field is invalid.']]);
        $this->assertGuest();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_confirm_passkey_based_registration_on_an_insecure_origin_when_it_has_not_been_manually_marked_as_trustworthy(): void
    {
        Event::fake(Registered::class);
        Config::set('app.debug', true);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['foo.com']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptionsTwo($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCA_whW46e5nw7iOM8BHvuPf4NfvpQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR_D-Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => ['The credential field is invalid.']]);
        $this->assertGuest();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::multiFactorCredentialModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_the_passkey_based_user_is_registered(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Registered::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $response = $this->postJson(route('register'), [
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

        $response->assertCreated();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $this->assertAuthenticatedAs($user);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(1, $credentials = LaravelAuth::multiFactorCredentialModel()::all());
        tap($credentials->first(), function (MultiFactorCredential $key) use ($user) {
            $this->assertSame('public-key-AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI_jN0CetpIkiw9--R0AF9a6OJnHD-G4aIWur-Pxj-sI9xDE-AVeQKve', $key->id);
            $this->assertSame($user->id, $key->user_id);
            $this->assertEquals(CredentialType::PUBLIC_KEY, $key->type);
            $this->assertEquals('User Passkey', $key->name);
            $this->assertSame('{"id":"AFkzwaxVuCUz4qFPaNAgnYgoZKKTtvGIAaIASAbnlHGy8UktdI\/jN0CetpIkiw9++R0AF9a6OJnHD+G4aIWur+Pxj+sI9xDE+AVeQKve","publicKey":"pQECAyYgASFYIE5LBFVDFc9vvqe+ZDYdDyLkGKfwzjN9kKoiUpetzHGbIlgg4UIBn36tGGSW+fWeTZNqFoK+kf3p6YS4qgbGkQ5u9CA=","signCount":1548688135,"userHandle":"1","transports":[]}', $key->secret);
        });
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->is($user));
        Carbon::setTestNow();
    }
}
