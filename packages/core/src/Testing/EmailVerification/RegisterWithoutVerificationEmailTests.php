<?php

namespace ClaudioDekker\LaravelAuth\Testing\EmailVerification;

use App\Models\User;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Session;

trait RegisterWithoutVerificationEmailTests
{
    /** @test */
    public function it_does_not_send_a_verification_email_for_password_based_registration_requests(): void
    {
        Notification::fake();
        $this->assertCount(0, User::all());

        $this->submitPasswordBasedRegisterAttempt();

        $this->assertCount(1, User::all());
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_does_not_send_a_verification_email_for_passkey_based_registration_requests(): void
    {
        Notification::fake();
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $this->submitPasskeyBasedRegisterAttempt();

        $this->assertCount(1, MultiFactorCredential::all());
        Notification::assertNothingSent();
    }
}
