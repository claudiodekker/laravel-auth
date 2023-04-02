<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Events\PasswordChanged;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;

trait SubmitChangePasswordTests
{
    /** @test */
    public function the_user_password_can_be_changed(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password' => 'something-more-secret',
                'new_password_confirmation' => 'something-more-secret',
            ]);

        $response->assertRedirect(route('auth.settings'));
        $response->assertSessionHas('status', __('laravel-auth::auth.settings.password-changed'));
        $this->assertTrue(password_verify('something-more-secret', $user->fresh()->password));
        Event::assertDispatched(PasswordChanged::class, fn (PasswordChanged $event) => $event->user->is($user));
    }

    /** @test */
    public function it_validates_that_the_current_password_is_required_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'new_password' => 'something-more-secret',
                'new_password_confirmation' => 'something-more-secret',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['current_password' => [__('validation.required', ['attribute' => 'current password'])]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_validates_that_the_current_password_is_valid_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'invalid-password',
                'new_password' => 'something-more-secret',
                'new_password_confirmation' => 'something-more-secret',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['current_password' => [__('validation.current_password')]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_validates_that_the_new_password_is_required_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password_confirmation' => 'something-more-secret',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['new_password' => [__('validation.required', ['attribute' => 'new password'])]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_validates_that_the_password_confirmation_is_required_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password' => 'something-more-secret',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['new_password' => [__('validation.confirmed', ['attribute' => 'new password'])]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_validates_that_the_password_is_confirmed_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password' => 'something-more-secret',
                'new_password_confirmation' => 'some-other-secret',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['new_password' => [__('validation.confirmed', ['attribute' => 'new password'])]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function it_validates_that_the_password_default_rules_are_applied_when_changing_the_user_password(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password' => 'foo',
                'new_password_confirmation' => 'foo',
            ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['new_password' => [__('validation.min.string', ['attribute' => 'new password', 'min' => 8])]], $response->exception->errors());
        $this->assertTrue(password_verify('password', $user->fresh()->password));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_password_cannot_be_changed_when_no_longer_in_sudo_mode(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser();

        $response = $this->actingAs($user)
            ->put(route('auth.settings.password'));

        $response->assertRedirect(route('auth.sudo_mode'));
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_password_cannot_be_changed_when_the_user_is_not_password_based(): void
    {
        Event::fake([PasswordChanged::class]);
        $user = $this->generateUser(['has_password' => false]);
        $this->enableSudoMode();

        $response = $this->actingAs($user)
            ->from(route('auth.settings'))
            ->put(route('auth.settings.password'), [
                'current_password' => 'password',
                'new_password' => 'something-more-secret',
                'new_password_confirmation' => 'something-more-secret',
            ]);

        $response->assertForbidden();
        Event::assertNothingDispatched();
    }

    /** @test */
    public function the_user_password_cannot_be_changed_when_not_authenticated(): void
    {
        $response = $this->put(route('auth.settings.password'));

        $response->assertRedirect(route('login'));
    }
}
