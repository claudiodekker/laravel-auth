<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Notifications\AccountRecoveryNotification;
use App\Providers\RouteServiceProvider;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;

trait SubmitRecoveryRequestTests
{
    /** @test */
    public function guests_can_request_an_account_recovery_link(): void
    {
        Notification::fake();
        $repository = Password::getRepository();
        $user = $this->generateUser();
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts(''));
        $this->expectTimebox();

        $response = $this->from('/foo')->post(route('recover-account'), [
            $this->usernameField() => $this->defaultUsername(),
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent', ['field' => $this->usernameField()]));
        $this->assertTrue($repository->recentlyCreatedToken($user));
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Notification::assertSentTo($user, AccountRecoveryNotification::class, function (AccountRecoveryNotification $notification) use ($repository, $user) {
            $action = Request::create($notification->toMail($user)->actionUrl);
            $route = Route::getRoutes()->match($action);

            $this->assertSame('recover-account.challenge', $route->getName());
            $this->assertSame($user->{$this->usernameField()}, $action->query($this->usernameField()));
            $this->assertTrue($repository->exists($user, $route->parameter('token')));

            return true;
        });
    }

    /** @test */
    public function users_cannot_request_an_account_recovery_link_when_authenticated(): void
    {
        Notification::fake();
        $this->actingAs($user = $this->generateUser());

        $response = $this->post(route('recover-account'), [
            $this->usernameField() => $this->defaultUsername(),
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertFalse(Password::getRepository()->recentlyCreatedToken($user));
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_validates_that_the_username_is_required_when_requesting_an_account_recovery_link(): void
    {
        Notification::fake();
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts(''));
        $this->expectTimebox();

        $response = $this->from('/foo')->post(route('recover-account'), [
            $this->usernameField() => '',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('validation.required', ['attribute' => $this->usernameField()])]], $response->exception->errors());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $response->assertSessionMissing('status');
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_cannot_send_an_account_recovery_link_to_an_user_that_does_not_exist(): void
    {
        Notification::fake();
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts(''));
        $this->expectTimebox();

        $response = $this->from('/foo')->post(route('recover-account'), [
            $this->usernameField() => $this->nonExistentUsername(),
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent', ['field' => $this->usernameField()]));
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_only_sends_a_fresh_recovery_link_when_one_has_not_been_sent_recently(): void
    {
        Carbon::setTestNow(now());
        Notification::fake();
        $repository = Password::getRepository();
        $user = $this->generateUser();
        $repository->create($user);
        Carbon::setTestNow(now()->addSeconds(59));
        $this->assertTrue($repository->recentlyCreatedToken($user));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        $this->assertSame(0, $this->getRateLimitAttempts(''));
        $this->expectTimebox();

        $response = $this->from('/foo')->post(route('recover-account'), [
            $this->usernameField() => $this->defaultUsername(),
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent', ['field' => $this->usernameField()]));
        $this->assertTrue($repository->recentlyCreatedToken($user));
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Notification::assertNothingSent();
        Carbon::setTestNow();
    }

    /** @test */
    public function account_recovery_requests_are_rate_limited_after_too_many_requests(): void
    {
        Carbon::setTestNow(now());
        Notification::fake();
        Event::fake([Lockout::class]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->post(route('recover-account'), [
            $this->usernameField() => $this->defaultUsername(),
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('laravel-auth::auth.recovery.throttle', ['seconds' => 60])]], $response->exception->errors());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Notification::assertNothingSent();
        Carbon::setTestNow();
    }
}
