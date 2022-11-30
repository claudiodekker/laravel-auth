<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use App\Providers\RouteServiceProvider;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;

trait EmailVerificationTests
{
    /** @test */
    public function the_user_can_request_an_email_verification_link(): void
    {
        Notification::fake();
        $this->enableSudoMode();
        $user = $this->generateUser(['email_verified_at' => null]);

        $response = $this->actingAs($user)
            ->post(route('verification.send'));

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionHas('status', __('laravel-auth::auth.verification.sent'));
        Notification::assertSentTo($user, VerifyEmail::class);
    }

    /** @test */
    public function the_user_cannot_request_an_email_verification_link_when_their_email_has_already_been_verified(): void
    {
        Notification::fake();
        $this->enableSudoMode();
        $user = $this->generateUser(['email_verified_at' => now()]);

        $response = $this->actingAs($user)
            ->post(route('verification.send'));

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionHas('status', __('laravel-auth::auth.verification.already-verified'));
        Notification::assertNothingSent();
    }

    /** @test */
    public function the_user_cannot_request_an_email_verification_link_when_no_longer_in_sudo_mode(): void
    {
        Notification::fake();
        $user = $this->generateUser(['email_verified_at' => null]);

        $response = $this->actingAs($user)
            ->post(route('verification.send'));

        $response->assertRedirect(route('auth.sudo_mode'));
        Notification::assertNothingSent();
    }

    /** @test */
    public function the_user_can_complete_the_email_verification_request(): void
    {
        Event::fake(Verified::class);
        $user = $this->generateUser(['email_verified_at' => null]);
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(Config::get('auth.verification.expire', 60)),
            ['id' => $user->id, 'hash' => sha1($user->email)]
        );

        $response = $this->actingAs($user)
            ->get($verificationUrl);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $response->assertSessionHas('status', __('laravel-auth::auth.verification.verified'));
        $this->assertNotNull($user->fresh()->email_verified_at);
        Event::assertDispatched(Verified::class, fn ($event) => $event->user->is($user));
    }

    /** @test */
    public function the_user_cannot_complete_the_email_verification_request_when_the_id_is_invalid(): void
    {
        Event::fake(Verified::class);
        $user = $this->generateUser(['email_verified_at' => null]);
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(Config::get('auth.verification.expire', 60)),
            ['id' => 7, 'hash' => sha1($user->email)]
        );

        $response = $this->actingAs($user)
            ->get($verificationUrl);

        $response->assertForbidden();
        $this->assertNull($user->fresh()->email_verified_at);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_complete_the_email_verification_request_when_the_hash_is_invalid(): void
    {
        Event::fake(Verified::class);
        $user = $this->generateUser(['email_verified_at' => null]);
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(Config::get('auth.verification.expire', 60)),
            ['id' => $user->id, 'hash' => sha1('invalid.email@example.com')]
        );

        $response = $this->actingAs($user)
            ->get($verificationUrl);

        $response->assertForbidden();
        $this->assertNull($user->fresh()->email_verified_at);
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_cannot_complete_the_email_verification_request_when_the_link_has_expired(): void
    {
        Carbon::setTestNow(now());
        Event::fake(Verified::class);
        $user = $this->generateUser(['email_verified_at' => null]);
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(Config::get('auth.verification.expire', 60)),
            ['id' => $user->id, 'hash' => sha1($user->email)]
        );

        Carbon::setTestNow(now()->addMinutes(61));
        $response = $this->actingAs($user)
            ->get($verificationUrl);

        $response->assertForbidden();
        $this->assertNull($user->fresh()->email_verified_at);
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }

    /** @test */
    public function the_user_cannot_complete_the_email_verification_request_when_it_has_already_been_verified(): void
    {
        Carbon::setTestNow(now());
        Event::fake(Verified::class);
        $user = $this->generateUser(['email_verified_at' => now()]);
        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(Config::get('auth.verification.expire', 60)),
            ['id' => $user->id, 'hash' => sha1($user->email)]
        );

        $response = $this->actingAs($user)
            ->get($verificationUrl);

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionHas('status', __('laravel-auth::auth.verification.already-verified'));
        $this->assertTrue($user->fresh()->email_verified_at->is(now()));
        Event::assertNothingDispatched();
        Carbon::setTestNow();
    }
}
