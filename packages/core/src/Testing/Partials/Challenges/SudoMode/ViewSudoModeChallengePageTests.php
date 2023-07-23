<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode;

use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Support\Facades\Session;

trait ViewSudoModeChallengePageTests
{
    /** @test */
    public function the_user_can_view_the_sudo_mode_page_when_required(): void
    {
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();
        LaravelAuth::multiFactorCredentialModel()::factory()->publicKey()->forUser($user)->create();
        $this->assertFalse(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->actingAs($user)->get(route('auth.sudo_mode'));

        $response->assertOk();
        $response->assertSessionHas('laravel-auth::sudo_mode.public_key_challenge_request_options');
    }

    /** @test */
    public function the_sudo_mode_page_does_not_initialize_a_public_key_challenge_when_the_user_has_no_public_key_credentials(): void
    {
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $user = $this->generateUser();
        $this->assertFalse(Session::has('laravel-auth::sudo_mode.public_key_challenge_request_options'));
        $this->expectTimebox();

        $response = $this->actingAs($user)->get(route('auth.sudo_mode'));

        $response->assertOk();
        $response->assertSessionMissing('laravel-auth::sudo_mode.public_key_challenge_request_options');
    }

    /** @test */
    public function the_user_cannot_view_the_sudo_mode_page_directly(): void
    {
        $user = $this->generateUser();

        $response = $this->actingAs($user)->get(route('auth.sudo_mode'));

        $response->assertStatus(400);
    }

    /** @test */
    public function guests_cannot_view_the_sudo_mode_page(): void
    {
        $response = $this->get(route('auth.sudo_mode'));

        $response->assertRedirect(route('login'));
    }
}
