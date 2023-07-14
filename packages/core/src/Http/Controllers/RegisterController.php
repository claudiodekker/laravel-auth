<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Concerns\Registration\PasskeyBasedRegistration;
use ClaudioDekker\LaravelAuth\Http\Concerns\Registration\PasswordBasedRegistration;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;

abstract class RegisterController
{
    use EmailBased;
    use EnablesSudoMode;
    use PasskeyBasedRegistration;
    use PasswordBasedRegistration;

    /**
     * Sends a response indicating that the user has successfully registered.
     *
     * @return mixed
     */
    abstract protected function sendRegisteredResponse(Request $request, Authenticatable $user);

    /**
     * Handle an incoming request to view the registration page.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function create(Request $request)
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @see static::sendPasskeyBasedRegistrationInitializedResponse()
     * @see static::sendInvalidPasskeyRegistrationStateResponse()
     * @see static::sendInvalidPasskeyResponse()
     * @see static::sendRegisteredResponse()
     *
     * @return mixed
     */
    public function store(Request $request)
    {
        if ($this->isPasswordBasedRegistrationAttempt($request)) {
            return $this->handlePasswordBasedRegistrationRequest($request);
        }

        return $this->handlePasskeyBasedRegistrationRequest($request);
    }

    /**
     * Handle an incoming registration cancellation request.
     *
     * @see static::sendInvalidPasskeyRegistrationStateResponse()
     * @see static::sendPasskeyRegistrationCancelledResponse()
     *
     * @return mixed
     */
    public function destroy(Request $request)
    {
        return $this->handlePasskeyBasedRegistrationCancellationRequest($request);
    }

    /**
     * Determine whether the registration attempt is password based.
     */
    protected function isPasswordBasedRegistrationAttempt(Request $request): bool
    {
        return $request->input('type') !== 'passkey';
    }

    /**
     * Authenticate the user into the application.
     */
    protected function authenticate(Authenticatable $user): void
    {
        Auth::login($user);
    }

    /**
     * Determine the URL to redirect to once the user has been registered.
     */
    protected function redirectUrl(Request $request, Authenticatable $user): string
    {
        return $this->redirectTo
            ?? RouteServiceProvider::HOME
            ?? '/';
    }

    /**
     * Send the email verification notification.
     */
    protected function sendEmailVerificationNotification(Authenticatable $user): void
    {
        $user->sendEmailVerificationNotification();
    }

    /**
     * Emits an event indicating that the user has been registered.
     */
    protected function emitRegisteredEvent(Authenticatable $user): void
    {
        Event::dispatch(new Registered($user));
    }
}
