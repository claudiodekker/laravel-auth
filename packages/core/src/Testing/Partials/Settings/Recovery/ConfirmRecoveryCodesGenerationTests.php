<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery;

use ClaudioDekker\LaravelAuth\Events\RecoveryCodesGenerated;
use ClaudioDekker\LaravelAuth\RecoveryCodeManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait ConfirmRecoveryCodesGenerationTests
{
    /** @test */
    public function it_saves_the_newly_generated_recovery_codes_when_a_valid_confirmation_code_was_provided(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        $this->enableSudoMode();
        $this->actingAs($user)->post(route('auth.settings.generate_recovery'));
        $codes = Session::get('auth.mfa_setup.pending_recovery_codes')->toArray();

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'), [
            'code' => $codes[3],
        ]);

        $response->assertRedirect(route('auth.settings'));
        $this->assertFalse(Session::has('auth.mfa_setup.pending_recovery_codes'));
        $this->assertSame($codes, $user->fresh()->recovery_codes);
        Event::assertDispatched(RecoveryCodesGenerated::class, fn (RecoveryCodesGenerated $event) => $event->user->is($user));
    }

    /** @test */
    public function a_confirmation_code_is_required_to_save_the_newly_generated_recovery_codes(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        $this->enableSudoMode();
        $this->actingAs($user)->post(route('auth.settings.generate_recovery'));
        $this->assertNotNull(Session::get('auth.mfa_setup.pending_recovery_codes'));

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'));

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.required', ['attribute' => 'code'])]], $response->exception->errors());
        $this->assertNull($user->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_confirmation_code_must_be_a_string_when_confirming_the_newly_generated_recovery_codes(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        $this->enableSudoMode();
        $this->actingAs($user)->post(route('auth.settings.generate_recovery'));
        $this->assertNotNull(Session::get('auth.mfa_setup.pending_recovery_codes'));

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'), [
            'code' => 123456,
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('validation.string', ['attribute' => 'code']),]], $response->exception->errors());
        $this->assertNull($user->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_confirmation_code_must_be_one_of_the_newly_generated_recovery_codes(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        $this->enableSudoMode();
        Session::put('auth.mfa_setup.pending_recovery_codes', RecoveryCodeManager::from(['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']));

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'), [
            'code' => 'ENVZV-GPP13',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['code' => [__('laravel-auth::auth.challenge.recovery')]], $response->exception->errors());
        $this->assertNull($user->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_fails_to_confirm_the_generation_of_new_recovery_codes_when_none_have_been_prepared(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'), [
            'code' => 'H4PFK-ENVZV',
        ]);

        $response->assertStatus(428);
        $this->assertNull($user->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_confirm_the_newly_generated_recovery_codes_when_no_longer_in_sudo_mode(): void
    {
        Event::fake(RecoveryCodesGenerated::class);
        $user = $this->generateUser();
        Session::put('auth.mfa_setup.pending_recovery_codes', $codes = ['H4PFK-ENVZV', 'PIPIM-7LTUT', 'GPP13-AEXMR', 'WGAHD-95VNQ', 'BSFYG-VFG2N', 'AWOPQ-NWYJX', '2PVJM-QHPBM', 'STR7J-5ND0P']);

        $response = $this->actingAs($user)->post(route('auth.settings.generate_recovery.store'), [
            'code' => $codes[3],
        ]);

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertTrue(Session::has('auth.mfa_setup.pending_recovery_codes'));
        $this->assertNull($user->fresh()->recovery_codes);
        Event::assertNothingDispatched();
    }
}
