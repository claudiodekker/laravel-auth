<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\Authenticated;
use ClaudioDekker\LaravelAuth\Events\AuthenticationFailed;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallenged;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait SubmitPasskeyBasedAuthenticationTests
{
    /** @test */
    public function it_authenticates_the_user_using_a_passkey(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_cannot_perform_passkey_based_authentication_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => 'clearly-invalid',
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
    }

    /** @test */
    public function it_validates_that_the_credential_is_required_during_passkey_based_authentication(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->generateUser(['id' => 1, 'has_password' => false]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('validation.required', ['attribute' => 'credential'])]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_when_no_options_were_initialized(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertStatus(428);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_when_the_credential_is_malformed(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2VV0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpIWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gZQlzBdA4d4yB1uSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQ6JebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_when_the_challenge_does_not_match(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptionsTwo()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_when_an_unknown_credential_was_provided(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $this->generateUser(['id' => 1, 'has_password' => false]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_when_the_user_handle_does_not_match(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"2","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_authenticates_the_user_using_a_passkey_on_an_insecure_origin_that_has_been_manually_marked_as_trustworthy(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        Config::set('app.debug', true);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['localhost']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ID_CFbjp7mfDuI4zwEe-49_g1-8',
            'secret' => '{"id":"ID\/CFbjp7mfDuI4zwEe+49\/g1+8=","publicKey":"pQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR\/D+Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptionsTwo()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
                    'signature' => 'MEUCIQC3KKOoro_3A8ssdIVA8sSnnbI3y_d-a_I_8eTSPgh23AIgWajRc28MIl89U_9uD-cLLPDDs8UpLo187_BC-YHpCTE',
                    'userHandle' => 'MQ',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_on_an_insecure_origin_that_has_been_manually_marked_as_trustworthy_when_debug_is_disabled(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        Config::set('app.debug', false);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['localhost']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ID_CFbjp7mfDuI4zwEe-49_g1-8',
            'secret' => '{"id":"ID\/CFbjp7mfDuI4zwEe+49\/g1+8=","publicKey":"pQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR\/D+Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptionsTwo()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
                    'signature' => 'MEUCIQC3KKOoro_3A8ssdIVA8sSnnbI3y_d-a_I_8eTSPgh23AIgWajRc28MIl89U_9uD-cLLPDDs8UpLo187_BC-YHpCTE',
                    'userHandle' => 'MQ',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_fails_to_authenticate_using_a_passkey_on_an_insecure_origin_when_it_has_not_been_manually_marked_as_trustworthy(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        Config::set('app.debug', true);
        Config::set('laravel-auth.webauthn.relying_party.potentially_trustworthy_origins', ['foo.com']);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ID_CFbjp7mfDuI4zwEe-49_g1-8',
            'secret' => '{"id":"ID\/CFbjp7mfDuI4zwEe+49\/g1+8=","publicKey":"pQECAyYgASFYIFZSx3fc0szMDz38Eu4ZBWjeAQMP0dWR\/D+Dy3RA1tktIlggJzLmQt5ydTQ6PXRF4GFCgWyXJBT0giypbK0wducMmW4=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptionsTwo()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'rawId' => 'ID_CFbjp7mfDuI4zwEe-49_g1-8',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSW1KOVVjS1dseFFlYjhWNE14U3JyZyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA',
                    'signature' => 'MEUCIQC3KKOoro_3A8ssdIVA8sSnnbI3y_d-a_I_8eTSPgh23AIgWajRc28MIl89U_9uD-cLLPDDs8UpLo187_BC-YHpCTE',
                    'userHandle' => 'MQ',
                ],
                'type' => 'public-key',
            ],
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.failed')]], $response->exception->errors());
        $this->assertTrue(Session::has('auth.login.passkey_authentication_options'));
        $this->assertGuest();
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(AuthenticationFailed::class, fn (AuthenticationFailed $event) => $event->username === null);
    }

    /** @test */
    public function it_sets_the_remember_cookie_when_the_user_authenticates_using_a_passkey_with_the_remember_option_enabled(): void
    {
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'remember' => 'on',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertHasRememberCookie($response, $user);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_sends_the_user_to_their_intended_location_when_authenticated_using_a_passkey(): void
    {
        Redirect::setIntendedUrl($redirectsTo = '/intended');
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => $redirectsTo]);
        $this->assertFalse(Session::has('auth.login.passkey_authentication_options'));
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_authenticated_using_a_passkey(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Authenticated::class, AuthenticationFailed::class, MultiFactorChallenged::class, SudoModeEnabled::class]);
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        Event::assertNotDispatched(AuthenticationFailed::class);
        Event::assertNotDispatched(MultiFactorChallenged::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Authenticated::class, fn (Authenticated $event) => $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function the_session_identifier_gets_regenerated_to_prevent_session_fixation_attacks_when_passkey_based_authentication_succeeds(): void
    {
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create([
            'id' => 'public-key-ea2KxTIqiH6GqbKePv4rwk8XWVE',
            'secret' => '{"id":"ea2KxTIqiH6GqbKePv4rwk8XWVE=","publicKey":"pQECAyYgASFYIEOExHX5IQpnF2dCG1fpw51gD7va0WxmKonfkDMWIRG9Ilggj7YxOrVEYp6EAeGNYwOlpd8FUmsqYyk0L0JIpNa1\/3A=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
        Session::put('auth.login.passkey_authentication_options', serialize($this->mockPasskeyRequestOptions()));
        $this->assertNotEmpty($previousId = session()->getId());

        $response = $this->postJson(route('login'), [
            'type' => 'passkey',
            'credential' => [
                'id' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE',
                'rawId' => 'ea2KxTIqiH6GqbKePv4rwk8XWVE=',
                'response' => [
                    'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjlLbm15VHhzNnpISkI3NWJoTEtndyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aHRlc3Qud3JwLmFwcCJ9',
                    'authenticatorData' => 'gEDJZQlzBdA4d4yB1qhuSL6J_Qix5U7E7xPSW4ls3BkdAAAAAA',
                    'signature' => 'MEUCIQDrwdR9l4JUpyrmQet636nFtW8UMdQJebPHkaX2B/snrgIgbktsWMHzYSOAhUyrymLzuLCXIZd3wSBDb9XSRPfcs0E=',
                    'userHandle' => 'MQ==',
                ],
                'type' => 'public-key',
            ],
        ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $this->assertFullyAuthenticatedAs($response, $user);
        $this->assertMissingRememberCookie($response, $user);
        $this->assertNotSame($previousId, session()->getId());
    }
}
