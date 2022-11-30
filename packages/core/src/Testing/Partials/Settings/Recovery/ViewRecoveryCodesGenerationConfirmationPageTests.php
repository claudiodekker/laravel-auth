<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery;

use Illuminate\Support\Facades\Session;

trait ViewRecoveryCodesGenerationConfirmationPageTests
{
    /** @test */
    public function the_user_can_view_the_page_used_to_confirm_the_newly_generated_recovery_codes(): void
    {
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_recovery_codes', ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']);

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.settings.generate_recovery.confirm'));

        $response->assertOk();
    }

    /** @test */
    public function the_user_cannot_view_the_page_used_to_confirm_new_recovery_codes_when_none_have_been_prepared(): void
    {
        $this->enableSudoMode();

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.settings.generate_recovery.confirm'));

        $response->assertStatus(428);
    }

    /** @test */
    public function the_user_cannot_view_the_page_used_to_confirm_the_newly_generated_recovery_codes_when_no_longer_in_sudo_mode(): void
    {
        Session::put('auth.mfa_setup.pending_recovery_codes', ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']);

        $response = $this->actingAs($this->generateUser())
            ->get(route('auth.settings.generate_recovery.confirm'));

        $response->assertRedirect(route('auth.sudo_mode'));
    }
}
