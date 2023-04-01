<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing\Partials;

trait RegisterViewTests
{
    /** @test */
    public function the_registration_page_uses_blade_views(): void
    {
        $response = $this->get(route('register'));

        $response->assertViewIs('auth.register');
    }
}
