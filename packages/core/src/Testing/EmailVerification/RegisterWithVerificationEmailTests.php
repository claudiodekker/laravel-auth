<?php

namespace ClaudioDekker\LaravelAuth\Testing\EmailVerification;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Session;

trait RegisterWithVerificationEmailTests
{
    /** @test */
    public function it_sends_a_verification_email_for_password_based_registration_requests(): void
    {
        Notification::fake();
        $this->assertCount(0, LaravelAuth::userModel()::all());

        $this->submitPasswordBasedRegisterAttempt();

        Notification::assertSentTo(LaravelAuth::userModel()::first(), VerifyEmail::class);
    }

    /** @test */
    public function it_sends_a_verification_email_for_passkey_based_registration_requests(): void
    {
        Notification::fake();
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $this->submitPasskeyBasedRegisterAttempt();

        Notification::assertSentTo($user, VerifyEmail::class);
    }
}
