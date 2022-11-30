<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery;

use ClaudioDekker\LaravelAuth\RecoveryCodeManager;
use Illuminate\Support\Facades\Session;

trait InitializeRecoveryCodesGenerationTests
{
    /** @test */
    public function the_user_can_initialize_the_generation_of_fresh_recovery_codes(): void
    {
        $this->enableSudoMode();
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_recovery_codes'));

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.settings.generate_recovery'));

        $response->assertOk();
        $this->assertInstanceOf(RecoveryCodeManager::class, $codes = Session::get('auth.mfa_setup.pending_recovery_codes'));
        $this->assertCount(8, $codes->toArray());
    }

    /** @test */
    public function the_user_cannot_initialize_the_generation_of_fresh_recovery_codes_when_no_longer_in_sudo_mode(): void
    {
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_recovery_codes'));

        $response = $this->actingAs($this->generateUser())
            ->post(route('auth.settings.generate_recovery'));

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::missing('auth.mfa_setup.pending_recovery_codes'));
    }
}
