<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit\Http\Middleware;

use ClaudioDekker\LaravelAuth\Http\Middleware\EnsurePasswordBasedUser;
use ClaudioDekker\LaravelAuth\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Factories\UserFactory;

class EnsurePasswordBasedUserTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Route::group(['middleware' => ['web']], function () {
            Route::get('/baz')->name('auth.password_based_only');
            Route::middleware(EnsurePasswordBasedUser::class)->get('/foo', function () {
                return 'bar';
            });
        });
    }

    /** @test */
    public function it_aborts_the_request_when_not_authenticated(): void
    {
        $response = $this->get('/foo');

        $response->assertStatus(401);
    }

    /** @test */
    public function it_aborts_the_request_when_the_user_does_not_have_a_password(): void
    {
        $user = UserFactory::new()->create();
        $user->has_password = false;

        $response = $this->actingAs($user)->get('/foo');

        $response->assertStatus(403);
    }

    /** @test */
    public function it_continues_when_the_user_has_a_password(): void
    {
        $user = UserFactory::new()->create();
        $user->has_password = true;

        $response = $this->actingAs($user)->get('/foo');

        $response->assertStatus(200);
    }
}
