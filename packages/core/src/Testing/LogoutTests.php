<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use Illuminate\Support\Facades\Session;

trait LogoutTests
{
    /** @test */
    public function the_user_can_be_signed_out(): void
    {
        $this->actingAs($this->generateUser());
        Session::put('some_random_key', 'some_random_value');

        $response = $this->delete(route('logout'));

        $response->assertRedirect(route('login'));
        $response->assertSessionMissing('some_random_key');
        $this->assertGuest();
    }
}
