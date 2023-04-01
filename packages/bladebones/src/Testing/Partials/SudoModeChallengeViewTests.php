<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use Illuminate\Support\Facades\Session;

trait SudoModeChallengeViewTests
{
    /** @test */
    public function the_sudo_mode_confirmation_page_uses_blade_views(): void
    {
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();

        $response = $this->actingAs($user)
            ->get(route('auth.sudo_mode'));

        $response->assertViewIs('auth.challenges.sudo_mode');
    }
}
