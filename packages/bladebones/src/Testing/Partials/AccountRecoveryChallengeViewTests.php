<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use Illuminate\Support\Facades\Password;

trait AccountRecoveryChallengeViewTests
{
    /** @test */
    public function the_account_recovery_challenge_page_uses_blade_views(): void
    {
        $user = $this->generateUser();
        $token = Password::getRepository()->create($user);

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            'email' => $user->getEmailForPasswordReset(),
        ]));

        $response->assertViewIs('auth.challenges.recovery');
        $this->assertSame($token, $response->viewData('token'));
    }
}
