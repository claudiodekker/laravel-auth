<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit\Http\Middleware;

use ClaudioDekker\LaravelAuth\Events\SudoModeChallenged;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Session;
use Orchestra\Testbench\Factories\UserFactory;

class EnsureSudoModeTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Route::group(['middleware' => ['web', 'auth']], function () {
            Route::get('/baz')->name('auth.sudo_mode');
            Route::middleware(EnsureSudoMode::class)->get('/foo', function () {
                return 'bar';
            });
        });
    }

    /** @test */
    public function it_continues_and_resets_the_sudo_mode_timeout_when_already_in_sudo_mode(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::CONFIRMED_AT_KEY, now()->subMinutes(14)->subSeconds(59)->unix());
        $user = UserFactory::new()->create();

        $response = $this->actingAs($user)->get('/foo');

        $response->assertOk();
        $this->assertSame('bar', $response->getContent());
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function it_redirects_the_user_to_the_challenge_page_when_not_in_sudo_mode(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        $user = UserFactory::new()->create();

        $response = $this->actingAs($user)->get('/foo');

        $response->assertRedirect('/baz');
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(SudoModeChallenged::class, function (SudoModeChallenged $event) use ($user) {
            return $event->request === request() && $event->user === $user;
        });
        Carbon::setTestNow();
    }

    /** @test */
    public function it_shows_a_message_indicating_that_sudo_mode_is_required_when_making_a_json_request_while_not_in_sudo_mode(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        $user = UserFactory::new()->create();

        $response = $this->actingAs($user)->getJson('/foo');

        $response->assertForbidden();
        $response->assertExactJson(['message' => 'Sudo-mode required.']);
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(SudoModeChallenged::class, function (SudoModeChallenged $event) use ($user) {
            return $event->request === request() && $event->user === $user;
        });
        Carbon::setTestNow();
    }

    /** @test */
    public function it_redirects_the_user_to_the_challenge_page_when_sudo_mode_has_expired(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Session::put(EnsureSudoMode::CONFIRMED_AT_KEY, now()->subMinutes(15)->unix());
        $user = UserFactory::new()->create();

        $response = $this->actingAs($user)->get('/foo');

        $response->assertRedirect('/baz');
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(SudoModeChallenged::class, function (SudoModeChallenged $event) use ($user) {
            return $event->request === request() && $event->user === $user;
        });
        Carbon::setTestNow();
    }
}
