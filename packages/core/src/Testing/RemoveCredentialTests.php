<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\LaravelAuth;

trait RemoveCredentialTests
{
    /** @test */
    public function the_user_can_remove_a_credential(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser();
        $credential = LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();

        $response = $this->actingAs($user)
            ->delete(route('auth.credentials.destroy', ['id' => $credential->id]));

        $response->assertRedirect(route('auth.settings'));
        $this->assertNull($credential->fresh());
    }

    /** @test */
    public function the_user_cannot_remove_a_credential_that_does_not_exist(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser();

        $response = $this->actingAs($user)
            ->delete(route('auth.credentials.destroy', ['id' => 1]));

        $response->assertNotFound();
    }

    /** @test */
    public function the_user_cannot_remove_a_credential_that_does_not_belong_to_them(): void
    {
        $this->enableSudoMode();
        $userA = $this->generateUser([$this->usernameField() => $this->defaultUsername()]);
        $userB = $this->generateUser([$this->usernameField() => $this->anotherUsername()]);
        $credential = LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($userA)->create();

        $response = $this->actingAs($userB)
            ->delete(route('auth.credentials.destroy', ['id' => $credential->id]));

        $response->assertNotFound();
        $this->assertNotNull($credential->fresh());
    }

    /** @test */
    public function the_user_cannot_remove_a_credential_when_no_longer_in_sudo_mode(): void
    {
        $user = $this->generateUser();
        $credential = LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();

        $response = $this->actingAs($user)
            ->delete(route('auth.credentials.destroy', ['id' => $credential->id]));

        $response->assertRedirect(route('auth.sudo_mode'));
        $this->assertNotNull($credential->fresh());
    }

    /** @test */
    public function a_credential_cannot_be_removed_when_the_user_is_not_password_based(): void
    {
        $this->enableSudoMode();
        $user = $this->generateUser(['has_password' => false]);
        $credential = LaravelAuth::multiFactorCredential()::factory()->totp()->forUser($user)->create();

        $response = $this->actingAs($user)
            ->delete(route('auth.credentials.destroy', ['id' => $credential->id]));

        $response->assertForbidden();
        $this->assertNotNull($credential->fresh());
    }
}
