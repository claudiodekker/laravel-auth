<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Http\Concerns\EmitsAuthenticationEvents;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Concerns\Registration\PasskeyBasedRegistration;
use ClaudioDekker\LaravelAuth\Http\Concerns\Registration\PasswordBasedRegistration;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

abstract class RegisterController
{
    use EmitsAuthenticationEvents;
    use EmailBased;
    use EnablesSudoMode;
    use PasskeyBasedRegistration;
    use PasswordBasedRegistration;

    /**
     * Sends a response indicating that the user has successfully registered.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return mixed
     */
    abstract protected function sendRegisteredResponse(Request $request, Authenticatable $user);

    /**
     * Handle an incoming request to view the registration page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\View\View
     */
    public function create(Request $request)
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendPasskeyBasedRegistrationInitializedResponse()
     * @see static::sendInvalidPasskeyRegistrationStateResponse()
     * @see static::sendInvalidPasskeyResponse()
     * @see static::sendRegisteredResponse()
     */
    public function store(Request $request)
    {
        if ($this->isPasswordBasedRegistrationAttempt($request)) {
            return $this->handlePasswordBasedRegistration($request);
        }

        return $this->handlePasskeyBasedRegistration($request);
    }

    /**
     * Handle an incoming registration cancellation request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendInvalidPasskeyRegistrationStateResponse()
     * @see static::sendPasskeyRegistrationCancelledResponse()
     */
    public function destroy(Request $request)
    {
        return $this->cancelPasskeyRegistration($request);
    }

    /**
     * Determine whether the registration attempt is password based.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isPasswordBasedRegistrationAttempt(Request $request): bool
    {
        return $request->input('type') !== 'passkey';
    }

    /**
     * Authenticate the user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function authenticate(Authenticatable $user): void
    {
        Auth::login($user);
    }

    /**
     * Determine the URL to redirect to once the user has been registered.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return string
     */
    protected function redirectUrl(Request $request, Authenticatable $user): string
    {
        return $this->redirectTo
            ?? RouteServiceProvider::HOME
            ?? '/';
    }

    /**
     * Send the email verification notification.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function sendEmailVerificationNotification(Authenticatable $user): void
    {
        $user->sendEmailVerificationNotification();
    }
}
