<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\PublicKey;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;
use ParagonIE\ConstantTime\Base64UrlSafe;

trait InitializePublicKeyCredentialRegistrationTests
{
    /** @test */
    public function the_user_can_initialize_a_new_public_key_credential_registration_process(): void
    {
        $this->enableSudoMode();
        Config::set('laravel-auth.webauthn.relying_party.id', 'localhost');
        Config::set('laravel-auth.webauthn.relying_party.name', 'Laravel Auth Package');
        $user = $this->generateUser();
        MultiFactorCredential::factory()->publicKey()->forUser($user)->create([
            'id' => CredentialType::PUBLIC_KEY->value.'-'.'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
            'secret' => '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB\/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","publicKey":"pQECAyYgASFYIBw\/HArIcANWNOBOxq3hH8lrHo9a17nQDxlqwybjDpHEIlggu3QUKIbALqsGuHfJI3LTKJSNmk0YCFb5oz1hjJidRMk=","signCount":0,"userHandle":"1","transports":[]}',
            'name' => 'existing-registration',
        ]);

        $this->actingAs($user)
            ->get(route('auth.credentials.register_public_key'))
            ->assertOk();

        /** @var PublicKeyCredentialCreationOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options = unserialize(Session::get('auth.mfa_setup.public_key_credential_creation_options'), [PublicKeyCredentialCreationOptions::class]));
        $this->assertNotNull($options->challenge());
        $this->assertNotEquals('', $options->challenge());
        $this->assertEquals([
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
            'excludeCredentials' => [
                [
                    'type' => 'public-key',
                    'id' => 'mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB_MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1-RIuTF9DUtEJZEEK',
                ],
            ],
            'attestation' => 'none',
            'authenticatorSelection' => [
                'userVerification' => 'discouraged',
                'residentKey' => 'preferred',
            ],
        ], $options->jsonSerialize());
    }

    /** @test */
    public function it_does_not_have_excluded_credentials_when_there_are_no_existing_public_key_credentials(): void
    {
        $this->enableSudoMode();
        Config::set('laravel-auth.webauthn.relying_party.id', 'laravel-auth.package');
        Config::set('laravel-auth.webauthn.relying_party.name', 'Example Application Name');

        $this->actingAs($user = $this->generateUser())
            ->get(route('auth.credentials.register_public_key'))
            ->assertOk();

        /** @var PublicKeyCredentialCreationOptions $options */
        $this->assertInstanceOf(PublicKeyCredentialCreationOptions::class, $options = unserialize(Session::get('auth.mfa_setup.public_key_credential_creation_options'), [PublicKeyCredentialCreationOptions::class]));
        $this->assertNotNull($options->challenge());
        $this->assertNotEquals('', $options->challenge());
        $this->assertEquals([
            'rp' => [
                'id' => 'laravel-auth.package',
                'name' => 'Example Application Name',
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
                'userVerification' => 'discouraged',
                'residentKey' => 'preferred',
            ],
        ], $options->jsonSerialize());
    }

    /** @test */
    public function the_user_cannot_initialize_a_new_public_key_credential_registration_process_when_no_longer_in_sudo_mode(): void
    {
        $this->assertTrue(Session::missing('auth.mfa_setup.public_key_credential_creation_options'));

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.credentials.register_public_key'));

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::missing('auth.mfa_setup.public_key_credential_creation_options'));
    }

    /** @test */
    public function a_new_public_key_credential_registration_process_cannot_be_initialized_when_the_user_is_not_password_based(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['has_password' => false]);

        $this->actingAs($user)
            ->get(route('auth.credentials.register_public_key'))
            ->assertForbidden();

        $this->assertTrue(Session::missing('auth.mfa_setup.public_key_credential_creation_options'));
    }
}
