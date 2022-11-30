<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor;

use App\Providers\RouteServiceProvider;

trait SubmitMultiFactorChallengeTests
{
    use SubmitMultiFactorChallengeUsingTotpCodeTests;
    use SubmitMultiFactorChallengeUsingPublicKeyCredentialTests;

    /** @test */
    public function it_cannot_complete_a_multi_factor_challenge_when_not_pre_authenticated(): void
    {
        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'credential' => [
                'id' => 'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                'type' => 'public-key',
                'rawId' => 'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                'response' => [
                    'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
                    'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew',
                    'signature' => 'MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=',
                    'userHandle' => null,
                ],
            ],
        ]);

        $response->assertRedirect(route('login'));
        $this->assertGuest();
    }

    /** @test */
    public function it_cannot_complete_a_multi_factor_challenge_when_already_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->postJson(route('login.challenge.multi_factor'), [
            'credential' => 'foo',
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
    }
}
