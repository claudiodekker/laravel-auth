<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use Carbon\Carbon;
use ClaudioDekker\LaravelAuth\Notifications\AccountRecoveryNotification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;

trait SubmitAccountRecoveryRequestTests
{
    /** @test */
    public function guests_can_request_an_account_recovery_link(): void
    {
        Notification::fake();
        $repository = Password::getRepository();
        $user = $this->generateUser();

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => $user->email,
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent'));
        $this->assertTrue($repository->recentlyCreatedToken($user));
        Notification::assertSentTo($user, AccountRecoveryNotification::class, function (AccountRecoveryNotification $notification) use ($repository, $user) {
            $action = Request::create($notification->toMail($user)->actionUrl);
            $route = Route::getRoutes()->match($action);

            $this->assertSame('recover-account.challenge', $route->getName());
            $this->assertSame($user->email, $action->query('email'));
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
            'email' => $user->email,
        ]);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertFalse(Password::getRepository()->recentlyCreatedToken($user));
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_validates_that_the_email_is_required_when_requesting_an_account_recovery_link(): void
    {
        Notification::fake();

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => '',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => ['The email field is required.']], $response->exception->errors());
        $response->assertSessionMissing('status');
        Notification::assertNothingSent();
    }

    /** @test */
    public function it_cannot_send_an_account_recovery_link_to_an_user_that_does_not_exist(): void
    {
        Notification::fake();

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => 'foo@example.com',
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent'));
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

        $response = $this->from('/foo')->post(route('recover-account'), [
            'email' => $user->email,
        ]);

        $response->assertRedirect('/foo');
        $response->assertSessionHas('status', __('laravel-auth::auth.recovery.sent'));
        $this->assertTrue($repository->recentlyCreatedToken($user));
        Notification::assertNothingSent();
        Carbon::setTestNow();
    }
}
