<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use ClaudioDekker\LaravelAuth\LaravelAuth;

trait CredentialsOverviewViewTests
{
    /** @test */
    public function the_credentials_overview_page_uses_blade_views(): void
    {
        $user = $this->generateUser();
        $totpOne = LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $totpTwo = LaravelAuth::multiFactorCredentialModel()::factory()->totp()->forUser($user)->create();
        $pubKeyOne = LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->get(route('auth.settings'));

        $response->assertViewIs('auth.settings.credentials');
        $this->assertCount(2, $response->viewData('totpCredentials'));
        $this->assertTrue($totpOne->is($response->viewData('totpCredentials')[0]));
        $this->assertTrue($totpTwo->is($response->viewData('totpCredentials')[1]));
        $this->assertCount(1, $response->viewData('publicKeyCredentials'));
        $this->assertTrue($pubKeyOne->is($response->viewData('publicKeyCredentials')[0]));
    }
}
