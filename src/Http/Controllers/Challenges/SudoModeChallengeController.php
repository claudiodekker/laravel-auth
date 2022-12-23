<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\PasswordChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\PublicKeyChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\EmitsAuthenticationEvents;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

abstract class SudoModeChallengeController
{
    use EmitsAuthenticationEvents;
    use EmailBased;
    use EnablesSudoMode;
    use PasswordChallenge;
    use PublicKeyChallenge;

    /**
     * Sends a response that displays the sudo-mode challenge page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions|null  $options
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, PublicKeyCredentialRequestOptions|null $options);

    /**
     * Sends a response indicating that sudo-mode has been enabled.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendSudoModeEnabledResponse(Request $request);

    /**
     * Sends a response indicating that sudo-mode is currently not required.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendConfirmationNotRequiredResponse(Request $request);

    /**
     * Display the sudo-mode challenge view.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendConfirmationNotRequiredResponse()
     * @see static::sendChallengePageResponse()
     */
    public function create(Request $request)
    {
        if (! $this->requiresConfirmation($request)) {
            return $this->sendConfirmationNotRequiredResponse($request);
        }

        return $this->sendChallengePageResponse($request, $this->initializePublicKeyChallenge($request));
    }

    /**
     * Determine whether the user is able to confirm the sudo-mode challenge using their password.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function supportsPasswordBasedConfirmation(Request $request): bool
    {
        return $request->user()->has_password;
    }

    /**
     * Verify the sudo-mode confirmation request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendConfirmationNotRequiredResponse()
     * @see static::sendRateLimitedResponse()
     * @see static::sendPasswordChallengeFailedResponse()
     * @see static::sendInvalidPublicKeyChallengeStateResponse()
     * @see static::sendPublicKeyChallengeFailedResponse()
     * @see static::sendSudoModeEnabledResponse()
     */
    public function store(Request $request)
    {
        if (! $this->requiresConfirmation($request)) {
            return $this->sendConfirmationNotRequiredResponse($request);
        }

        if ($this->isPasswordBasedConfirmationRequest($request)) {
            return $this->handlePasswordChallengeRequest($request);
        }

        return $this->handlePublicKeyChallengeRequest($request);
    }

    /**
     * Determines if the application has requested the user to enter sudo-mode.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function requiresConfirmation(Request $request): bool
    {
        return $request->session()->has(EnsureSudoMode::REQUIRED_AT_KEY);
    }

    /**
     * Determine if the given request is a password based confirmation request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isPasswordBasedConfirmationRequest(Request $request): bool
    {
        return $request->has('password') && $this->supportsPasswordBasedConfirmation($request);
    }

    /**
     * Sends a response indicating that the password challenge has succeeded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function sendPasswordChallengeSuccessfulResponse(Request $request)
    {
        $this->clearPublicKeyChallengeOptions($request);

        $this->enableSudoMode($request);
        $this->emitSudoModeEnabledEvent($request);

        return $this->sendSudoModeEnabledResponse($request);
    }

    /**
     * Sends a response indicating that the public key challenge has succeeded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function sendPublicKeyChallengeSuccessfulResponse(Request $request)
    {
        $this->enableSudoMode($request);
        $this->emitSudoModeEnabledEvent($request);

        return $this->sendSudoModeEnabledResponse($request);
    }

    /**
     * Determine the URL that the user intended to visit (if any) prior to receiving a sudo-mode challenge.
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
        return Str::transliterate(Str::lower(Auth::id().'|'.$request->ip().'|sudo'));
    }

    /**
     * Determine the identifier used to track the public key challenge options state.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function publicKeyChallengeOptionsKey(Request $request): string
    {
        return 'laravel-auth::sudo_mode.public_key_challenge_request_options';
    }
}
