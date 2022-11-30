<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\PublicKey;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;

trait ConfirmPublicKeyCredentialRegistrationTests
{
    /** @test */
    public function the_user_can_confirm_the_registration_of_a_public_key_credential(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
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

        $response->assertCreated();
        $this->assertFalse(Session::has('auth.mfa_setup.public_key_credential_creation_options'));
        $this->assertCount(1, $credentials = MultiFactorCredential::all());
        tap($credentials->first(), function (MultiFactorCredential $key) {
            $this->assertSame('public-key-mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK', $key->id);
            $this->assertSame(Auth::id(), $key->user_id);
            $this->assertEquals(CredentialType::PUBLIC_KEY, $key->type);
            $this->assertEquals('Example Credential', $key->name);
            $this->assertSame('{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB\/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","publicKey":"pQECAyYgASFYIBw\/HArIcANWNOBOxq3hH8lrHo9a17nQDxlqwybjDpHEIlggu3QUKIbALqsGuHfJI3LTKJSNmk0YCFb5oz1hjJidRMk=","signCount":0,"userHandle":"1","transports":[]}', $key->secret);
        });
    }

    /** @test */
    public function the_name_field_is_required_when_registering_a_public_key_credential(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
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

        $response->assertJsonValidationErrors([
            'name' => 'The name field is required.',
        ]);

        $this->assertCount(0, MultiFactorCredential::all());
        $this->assertTrue(Session::has('auth.mfa_setup.public_key_credential_creation_options'));
    }

    /** @test */
    public function the_credential_field_is_required_when_registering_a_public_key_credential(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
        ]);

        $response->assertJsonValidationErrors([
            'credential' => 'The credential field is required.',
        ]);

        $this->assertCount(0, MultiFactorCredential::all());
        $this->assertTrue(Session::has('auth.mfa_setup.public_key_credential_creation_options'));
    }

    /** @test */
    public function the_user_cannot_confirm_the_registration_of_a_public_key_credential_when_no_options_were_initialized(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
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

        $response->assertStatus(428);
        $this->assertCount(0, MultiFactorCredential::all());
        $this->assertFalse(Session::has('auth.mfa_setup.public_key_credential_creation_options'));
    }

    /** @test */
    public function the_user_cannot_confirm_the_registration_of_a_public_key_credential_that_is_already_registered(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);
        $existingCredential = MultiFactorCredential::factory()->publicKey()->create([
            'id' => 'public-key-mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
            'name' => 'existing-registration',
            'secret' => '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB\/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","publicKey":"pQECAyYgASFYIBw\/HArIcANWNOBOxq3hH8lrHo9a17nQDxlqwybjDpHEIlggu3QUKIbALqsGuHfJI3LTKJSNmk0YCFb5oz1hjJidRMk=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
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
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertTrue(Session::has('auth.mfa_setup.public_key_credential_creation_options'));

        $this->assertCount(1, $credentials = MultiFactorCredential::all());
        $this->assertTrue($credentials->first()->is($existingCredential));
    }

    /** @test */
    public function the_user_cannot_confirm_the_registration_of_a_public_key_credential_that_is_malformed(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['id' => 1]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Malformed Credential',
            'credential' => [
                'id' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
                'rawId' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiI5V3FncFJJWXZHTUNVWWlGVDIwbzFVNp1NHRLUDd3UmNyRTI2enMxemM0TEh5UGludlBHUzg2d3U2YkR2cHdidDhYcDJiUTNWQlJTUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
                    'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjkSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzAAAAAAAAAAAAYJjIobiMfS7pLMMQTjIzBw3+hADjTsu6nVoWkEO3TrVYkdnFQfzDW2cVEYtnL4ErykiC295iEnvZTzRvbGIKI7mOYjYp2DoOoUVcZptFbLLjRtqZtfkSLkxfQ1LRCWRBCqUBAgMmIAEhWCAcPxwKyHADVjTgTsat4R/Jax6PWte50A8ZasMm4w6RxCJYILt0FCiGwC6rBrh3ySNy0yiUjZpNGAhW+aM9YYyYnUTJ',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['credential' => [__('laravel-auth::auth.challenge.public-key')]]);
        $this->assertTrue(Session::has('auth.mfa_setup.public_key_credential_creation_options'));

        $this->assertCount(0, MultiFactorCredential::all());
    }

    /** @test */
    public function the_user_cannot_confirm_the_registration_of_a_public_key_credential_when_no_longer_in_sudo_mode(): void
    {
        $user = $this->generateUser(['id' => 1]);
        $options = $this->mockPublicKeyCreationOptions($user);
        Session::put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));

        $response = $this->actingAs($user)->postJson(route('auth.credentials.register_public_key.store'), [
            'name' => 'Example Credential',
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

        $response->assertForbidden();
        $response->assertExactJson(['message' => 'Sudo-mode required.']);
        $this->assertCount(0, MultiFactorCredential::all());
        $this->assertTrue(Session::has('auth.mfa_setup.public_key_credential_creation_options'));
    }
}
