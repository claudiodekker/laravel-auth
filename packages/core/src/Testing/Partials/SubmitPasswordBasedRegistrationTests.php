<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Validation\ValidationException;

trait SubmitPasswordBasedRegistrationTests
{
    /** @test */
    public function it_registers_the_user_using_an_username_and_password(): void
    {
        Event::fake(Registered::class);
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->expectTimeboxWithEarlyReturn();
        $this->hitRateLimiter(1, '');
        $this->hitRateLimiter(1, $ipKey = 'ip::127.0.0.1');

        $response = $this->submitPasswordBasedRegisterAttempt();

        $this->assertCount(1, $users = LaravelAuth::userModel()::all());
        $user = tap($users->first(), function ($user) {
            $this->assertSame('Claudio Dekker', $user->name);
            $this->assertSame($this->defaultUsername(), $user->{$this->usernameField()});
            $this->assertTrue(password_verify('password', $user->password));
            $this->assertTrue($user->has_password);
            $this->assertAuthenticatedAs($user);
        });
        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->is($user));
        $this->assertSame(2, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts($ipKey));
    }

    /** @test */
    public function it_cannot_perform_password_based_registration_when_authenticated(): void
    {
        $this->actingAs($this->generateUser());

        $response = $this->submitPasswordBasedRegisterAttempt([$this->usernameField() => '']);

        $response->assertRedirect(RouteServiceProvider::HOME);
        $this->assertCount(1, LaravelAuth::userModel()::all());
    }

    /** @test */
    public function it_validates_that_the_name_is_required_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['name' => '']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.required', ['attribute' => 'name'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_name_is_a_string_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['name' => 123]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.string', ['attribute' => 'name'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_name_does_not_exceed_255_characters_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['name' => str_repeat('a', 256)]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['name' => [__('validation.max.string', ['attribute' => 'name', 'max' => 255])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_username_is_required_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt([$this->usernameField() => '']);

        $this->assertUsernameRequiredValidationError($response);
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_username_does_not_exceed_255_characters_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt([$this->usernameField() => $this->tooLongUsername()]);

        $this->assertUsernameTooLongValidationError($response);
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_username_is_a_string_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt([$this->usernameField() => UploadedFile::fake()->image('username.jpg')]);

        $this->assertUsernameMustBeAStringValidationError($response);
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_email_is_required_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['email' => '']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.required', ['attribute' => 'email'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_email_does_not_exceed_255_characters_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['email' => str_repeat('a', 256).'@example.com']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.max.string', ['attribute' => 'email', 'max' => 255])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_email_is_valid_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['email' => 'foo']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['email' => [__('validation.email', ['attribute' => 'email'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_user_does_not_already_exist_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $this->generateUser([$this->usernameField() => $this->defaultUsername()]);

        $response = $this->submitPasswordBasedRegisterAttempt([$this->usernameField() => $this->defaultUsername()]);

        $this->assertUsernameAlreadyExistsValidationError($response);
        $this->assertCount(1, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_is_required_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['password' => '']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.required', ['attribute' => 'password'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_confirmation_is_required_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['password_confirmation' => '']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.confirmed', ['attribute' => 'password'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_is_confirmed_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt(['password_confirmation' => 'invalid-password-confirmation']);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.confirmed', ['attribute' => 'password'])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_validates_that_the_password_default_rules_are_applied_during_password_based_registration(): void
    {
        $this->expectTimebox();

        $response = $this->submitPasswordBasedRegisterAttempt([
            'password' => 'foo',
            'password_confirmation' => 'foo',
        ]);

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame(['password' => [__('validation.min.string', ['attribute' => 'password', 'min' => 8])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(1, $this->getRateLimitAttempts('ip::127.0.0.1'));
    }

    /** @test */
    public function it_automatically_enables_sudo_mode_when_registered_using_an_username_and_password(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Registered::class, SudoModeEnabled::class]);
        $this->expectTimeboxWithEarlyReturn();

        $response = $this->submitPasswordBasedRegisterAttempt();

        $this->assertCount(1, $users = LaravelAuth::userModel()::all());
        $user = tap($users->first(), function ($user) {
            $this->assertSame('Claudio Dekker', $user->name);
            $this->assertSame($this->defaultUsername(), $user->{$this->usernameField()});
            $this->assertTrue(password_verify('password', $user->password));
            $this->assertTrue($user->has_password);
            $this->assertAuthenticatedAs($user);
        });

        $response->assertExactJson(['redirect_url' => RouteServiceProvider::HOME]);
        $response->assertSessionMissing(EnsureSudoMode::REQUIRED_AT_KEY);
        $response->assertSessionHas(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        Event::assertNotDispatched(SudoModeEnabled::class);
        Event::assertDispatched(Registered::class, fn (Registered $event) => $event->user->is($user));
        $this->assertSame(1, $this->getRateLimitAttempts(''));
        $this->assertSame(0, $this->getRateLimitAttempts('ip::127.0.0.1'));
        Carbon::setTestNow();
    }

    /** @test */
    public function password_based_registration_requests_are_rate_limited_after_too_many_global_requests_to_sensitive_endpoints(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Registered::class, SudoModeEnabled::class]);
        $this->hitRateLimiter(250, '');

        $response = $this->submitPasswordBasedRegisterAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Registered::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
        Carbon::setTestNow();
    }

    /** @test */
    public function password_based_registration_requests_are_rate_limited_after_too_many_failed_attempts_from_one_ip_address(): void
    {
        Carbon::setTestNow(now());
        Event::fake([Lockout::class, Registered::class, SudoModeEnabled::class]);
        $this->hitRateLimiter(5, 'ip::127.0.0.1');

        $response = $this->submitPasswordBasedRegisterAttempt();

        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('laravel-auth::auth.throttle', ['seconds' => 60])]], $response->exception->errors());
        $this->assertCount(0, LaravelAuth::userModel()::all());
        Event::assertDispatched(Lockout::class, fn (Lockout $event) => $event->request === request());
        Event::assertNotDispatched(Registered::class);
        Event::assertNotDispatched(SudoModeEnabled::class);
    }
}
