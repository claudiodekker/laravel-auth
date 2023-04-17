<?php

namespace ClaudioDekker\LaravelAuth\Testing\EmailVerification;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Session;

trait RegisterWithoutVerificationEmailTests
{
    /** @test */
    public function it_does_not_send_a_verification_email_for_password_based_registration_requests(): void
    {
        Notification::fake();
        $this->assertCount(0, LaravelAuth::userModel()::all());

        $this->submitPasswordBasedRegisterAttempt();

        $this->assertCount(1, LaravelAuth::userModel()::all());
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_does_not_send_a_verification_email_for_passkey_based_registration_requests(): void
    {
        Notification::fake();
        $user = $this->generateUser(['id' => 1, 'has_password' => false]);
        $options = $this->mockPasskeyCreationOptions($user);
        Session::put('auth.register.passkey_creation_options', serialize($options));

        $this->postJson(route('register'), [
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

        $this->assertCount(1, LaravelAuth::multiFactorCredentialModel()::all());
        Notification::assertNothingSent();
    }
}
