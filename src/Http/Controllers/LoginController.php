<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Http\Concerns\EmitsAuthenticationEvents;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Concerns\HandlesLogouts;
use ClaudioDekker\LaravelAuth\Http\Concerns\Login\PasskeyBasedAuthentication;
use ClaudioDekker\LaravelAuth\Http\Concerns\Login\PasswordBasedAuthentication;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

abstract class LoginController
{
    use EmailBased;
    use EmitsAuthenticationEvents;
    use EnablesSudoMode;
    use HandlesLogouts;
    use PasskeyBasedAuthentication;
    use PasswordBasedAuthentication;

    /**
     * Sends a response that displays the login page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions  $options
     * @return mixed
     */
    abstract protected function sendLoginPageResponse(Request $request, PublicKeyCredentialRequestOptions $options);

    /**
     * Sends a response indicating that the user has been authenticated successfully.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return mixed
     */
    abstract protected function sendAuthenticatedResponse(Request $request, Authenticatable $user);

    /**
     * Sends a response indicating that authentication has failed.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendAuthenticationFailedResponse(Request $request);

    /**
     * Sends a response indicating that the user has been signed out.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendLoggedOutResponse(Request $request);

    /**
     * Handle an incoming request to view the login page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendLoginPageResponse()
     */
    public function create(Request $request)
    {
        $options = $this->initializePasskeyAuthenticationOptions($request);

        return $this->sendLoginPageResponse($request, $options);
    }

    /**
     * Handle an incoming authentication request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendInvalidPasskeyAuthenticationStateResponse()
     * @see static::sendMultiFactorChallengeResponse()
     * @see static::sendAuthenticationFailedResponse()
     * @see static::sendAuthenticatedResponse()
     */
    public function store(Request $request)
    {
        if ($this->isPasswordBasedAuthenticationAttempt($request)) {
            return $this->handlePasswordBasedAuthentication($request);
        }

        return $this->handlePasskeyBasedAuthentication($request);
    }

    /**
     * Determine whether the authentication attempt is password based.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isPasswordBasedAuthenticationAttempt(Request $request): bool
    {
        return $request->input('type') !== 'passkey';
    }

    /**
     * Sign the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendLoggedOutResponse()
     */
    public function destroy(Request $request)
    {
        $this->logout($request);

        return $this->sendLoggedOutResponse($request);
    }

    /**
     * Fully authenticate the user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    protected function authenticate(Authenticatable $user, bool $remember = false): void
    {
        Auth::login($user, $remember);
    }

    /**
     * Determines whether the user should be authenticated indefinitely or until they manually logout.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isRememberingUser(Request $request): bool
    {
        return $request->boolean('remember');
    }

    /**
     * Resolve the URL that the user intended to visit (if any) prior to authentication.
     *
     * @see \Illuminate\Routing\Redirector::intended
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function intendedLocation(Request $request): string
    {
        return $request->session()->pull('url.intended')
            ?? $this->redirectTo
            ?? RouteServiceProvider::HOME
            ?? '/';
    }

    /**
     * Get the rate limiting throttle key for the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function throttleKey(Request $request): string
    {
        return Str::transliterate(Str::lower($request->input($this->usernameField())).'|'.$request->ip());
    }
}
