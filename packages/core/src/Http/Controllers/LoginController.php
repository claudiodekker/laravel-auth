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
use Illuminate\Cache\RateLimiting\Limit;
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
     * @return mixed
     */
    abstract protected function sendLoginPageResponse(Request $request, PublicKeyCredentialRequestOptions $options);

    /**
     * Sends a response indicating that the user has been authenticated successfully.
     *
     * @return mixed
     */
    abstract protected function sendAuthenticatedResponse(Request $request, Authenticatable $user);

    /**
     * Sends a response indicating that authentication has failed.
     *
     * @return mixed
     */
    abstract protected function sendAuthenticationFailedResponse(Request $request);

    /**
     * Sends a response indicating that the user has been signed out.
     *
     * @return mixed
     */
    abstract protected function sendLoggedOutResponse(Request $request);

    /**
     * Handle an incoming request to view the login page.
     *
     * @see static::sendLoginPageResponse()
     *
     * @return mixed
     */
    public function create(Request $request)
    {
        $options = $this->initializePasskeyAuthenticationOptions($request);

        return $this->sendLoginPageResponse($request, $options);
    }

    /**
     * Handle an incoming authentication request.
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendInvalidPasskeyAuthenticationStateResponse()
     * @see static::sendMultiFactorChallengeResponse()
     * @see static::sendAuthenticationFailedResponse()
     * @see static::sendAuthenticatedResponse()
     *
     * @return mixed
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
     */
    protected function isPasswordBasedAuthenticationAttempt(Request $request): bool
    {
        return $request->input('type') !== 'passkey';
    }

    /**
     * Sign the user out of the application.
     *
     * @see static::sendLoggedOutResponse()
     *
     * @return mixed
     */
    public function destroy(Request $request)
    {
        $this->logout($request);

        return $this->sendLoggedOutResponse($request);
    }

    /**
     * Fully authenticate the user into the application.
     */
    protected function authenticate(Authenticatable $user, bool $remember = false): void
    {
        Auth::login($user, $remember);
    }

    /**
     * Determines whether the user should be authenticated indefinitely or until they manually logout.
     */
    protected function isRememberingUser(Request $request): bool
    {
        return $request->boolean('remember');
    }

    /**
     * Resolve the URL that the user intended to visit (if any) prior to authentication.
     *
     * @see \Illuminate\Routing\Redirector::intended
     */
    protected function intendedLocation(Request $request): string
    {
        return $request->session()->pull('url.intended')
            ?? $this->redirectTo
            ?? RouteServiceProvider::HOME
            ?? '/';
    }

    /**
     * Determine the rate limits that apply to the request.
     */
    protected function rateLimits(Request $request): array
    {
        $limits = [
            Limit::perMinute(250),
            Limit::perMinute(5)->by('ip::'.$request->ip()),
        ];

        if ($this->isPasswordBasedAuthenticationAttempt($request)) {
            $limits[] = Limit::perMinute(5)->by('username::'.Str::transliterate(Str::lower($request->input($this->usernameField()))));
        }

        return $limits;
    }
}
