<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;

trait ViewRegistrationPageTests
{
    /** @test */
    public function the_register_page_can_be_viewed(): void
    {
        $response = $this->get(route('register'));

        $response->assertOk();
    }

    /** @test */
    public function the_register_page_cannot_be_viewed_when_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->get(route('register'));

        $response->assertRedirect(RouteServiceProvider::HOME);
    }
}
