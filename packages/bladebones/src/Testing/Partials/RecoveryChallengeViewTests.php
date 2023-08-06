<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use Illuminate\Support\Facades\Password;

trait RecoveryChallengeViewTests
{
    /** @test */
    public function the_account_recovery_challenge_page_uses_blade_views(): void
    {
        $user = $this->generateUser(['recovery_codes' => ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']]);
        $token = Password::getRepository()->create($user);

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            $this->usernameField() => $user->{$this->usernameField()},
        ]));

        $response->assertViewIs('auth.challenges.recovery');
        $this->assertSame($token, $response->viewData('token'));
    }
}
