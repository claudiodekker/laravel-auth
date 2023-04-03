<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode;

use ClaudioDekker\LaravelAuth\Events\SudoModeChallenged;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait ConfirmSudoModeUsingPasswordTests
{
    /** @test */
    public function a_password_based_user_can_confirm_sudo_mode_using_a_password(): void
    {
        Carbon::setTestNow(now());
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Redirect::setIntendedUrl($redirectsTo = '/intended');
        $user = $this->generateUser();
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $this->actingAs($user)->get(route('auth.sudo_mode'));

        $response = $this->actingAs($user)
            ->post(route('auth.sudo_mode'), [
                'password' => 'password',
            ]);

        $response->assertOk();
        $response->assertExactJson(['redirect_url' => $redirectsTo]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        Event::assertNotDispatched(SudoModeChallenged::class);
        Event::assertDispatched(SudoModeEnabled::class, fn (SudoModeEnabled $event) => $event->request === request() && $event->user->is($user));
        Carbon::setTestNow();
    }

    /** @test */
    public function a_password_based_user_cannot_confirm_sudo_mode_when_the_provided_password_is_invalid(): void
    {
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Carbon::setTestNow(now());
        $user = $this->generateUser();
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());

        $response = $this->actingAs($user)
            ->from(route('auth.sudo_mode'))
            ->post(route('auth.sudo_mode'), [
                'password' => 'invalid-password',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('laravel-auth::auth.password')]], $response->exception->errors());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Carbon::setTestNow();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function a_password_based_user_cannot_use_a_password_to_confirm_sudo_mode_when_there_is_no_active_challenge(): void
    {
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Carbon::setTestNow(now());
        Redirect::setIntendedUrl('/unexpected');
        $user = $this->generateUser();

        $response = $this->actingAs($user)
            ->post(route('auth.sudo_mode'), [
                'password' => 'password',
            ]);

        $response->assertStatus(400);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function a_passwordless_user_cannot_confirm_sudo_mode_using_a_password(): void
    {
        Event::fake([SudoModeChallenged::class, SudoModeEnabled::class]);
        Carbon::setTestNow(now());
        $user = $this->generateUser(['has_password' => false]);
        Session::put(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());

        $response = $this->actingAs($user)
            ->post(route('auth.sudo_mode'), [
                'password' => 'password',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['credential' => [__('validation.required', ['attribute' => 'credential'])]], $response->exception->errors());
        $response->assertSessionHas(EnsureSudoMode::REQUIRED_AT_KEY, now()->unix());
        $response->assertSessionMissing(EnsureSudoMode::CONFIRMED_AT_KEY);
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }
}
