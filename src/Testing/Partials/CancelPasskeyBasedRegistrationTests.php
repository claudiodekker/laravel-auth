<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Models\User;
use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use ParagonIE\ConstantTime\Base64UrlSafe;

trait CancelPasskeyBasedRegistrationTests
{
    /** @test */
    public function it_releases_the_claimed_user_when_canceling_passkey_based_registration(): void
    {
        Event::fake([Registered::class]);
        $this->initializePasskeyBasedRegisterAttempt();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertGuest();
        $this->assertCount(1, $users = User::all());
        tap($users->first(), function (User $user) {
            $this->assertSame('Claudio Dekker', $user->name);
            $this->assertSame($this->defaultUsername(), $user->{$this->usernameField()});
            $this->assertTrue(password_verify('AUTOMATICALLY-GENERATED-PASSWORD-HASH', $user->password));
            $this->assertFalse($user->has_password);
        });

        $response = $this->deleteJson(route('register'));

        $response->assertStatus(200);
        $response->assertJson(['message' => 'The passkey registration has been cancelled.']);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, User::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_cancel_passkey_based_registration_when_authenticated(): void
    {
        Event::fake([Registered::class]);
        $this->initializePasskeyBasedRegisterAttempt();
        $this->assertCount(1, $users = User::all());
        $this->actingAs($users->first());
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));

        $response = $this->deleteJson(route('register'));

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(1, User::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_cancel_passkey_based_registration_when_no_options_were_initialized(): void
    {
        Event::fake([Registered::class]);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));

        $response = $this->deleteJson(route('register'));

        $response->assertStatus(428);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertGuest();
        Event::assertNothingDispatched();
    }
}
