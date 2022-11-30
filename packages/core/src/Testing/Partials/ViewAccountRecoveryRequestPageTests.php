<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;

trait ViewAccountRecoveryRequestPageTests
{
    /** @test */
    public function the_account_recovery_request_page_can_be_viewed(): void
    {
        $response = $this->get(route('recover-account'));

        $response->assertOk();
    }

    /** @test */
    public function the_account_recovery_request_page_cannot_be_viewed_when_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->get(route('recover-account'));

        $response->assertRedirect(RouteServiceProvider::HOME);
    }
}
