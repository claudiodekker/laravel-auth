<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

trait CancelPasskeyBasedRegistrationTests
{
    /** @test */
    public function it_releases_the_claimed_user_when_canceling_passkey_based_registration(): void
    {
        Event::fake([Registered::class]);
        $this->initializePasskeyBasedRegisterAttempt();
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertGuest();
        $this->assertCount(1, $users = LaravelAuth::userModel()::all());
        tap($users->first(), function ($user) {
            $this->assertSame('Claudio Dekker', $user->name);
            $this->assertSame($this->defaultUsername(), $user->{$this->usernameField()});
            $this->assertTrue(password_verify('AUTOMATICALLY-GENERATED-PASSWORD-HASH', $user->password));
            $this->assertFalse($user->has_password);
        });
        $this->expectTimebox();

        $response = $this->deleteJson(route('register'));

        $response->assertStatus(200);
        $response->assertJson(['message' => 'The passkey registration has been cancelled.']);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(0, LaravelAuth::userModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_cancel_passkey_based_registration_when_authenticated(): void
    {
        Event::fake([Registered::class]);
        $this->initializePasskeyBasedRegisterAttempt();
        $this->assertCount(1, $users = LaravelAuth::userModel()::all());
        $this->actingAs($users->first());
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));

        $response = $this->deleteJson(route('register'));

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertTrue(Session::has('auth.register.passkey_creation_options'));
        $this->assertCount(1, LaravelAuth::userModel()::all());
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_cannot_cancel_passkey_based_registration_when_no_options_were_initialized(): void
    {
        Event::fake([Registered::class]);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->expectTimebox();

        $response = $this->deleteJson(route('register'));

        $response->assertStatus(428);
        $this->assertFalse(Session::has('auth.register.passkey_creation_options'));
        $this->assertGuest();
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function passkey_based_registration_cancellation_requests_are_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Registered::class]);
        $this->hitRateLimiter(250, '');

        $response = $this->deleteJson(route('register'));

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Registered::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function passkey_based_registration_cancellation_requests_are_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Registered::class]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->deleteJson(route('register'));

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Registered::class);
        Carbon::setTestNow();
    }
}
