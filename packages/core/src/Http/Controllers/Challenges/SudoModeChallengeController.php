<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use App\Providers\RouteServiceProvider;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsLockoutEvent;
use ClaudioDekker\LaravelAuth\Events\SudoModeEnabled;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\PasswordChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\PublicKeyChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;

abstract class SudoModeChallengeController
{
    use EmailBased;
    use EmitsLockoutEvent;
    use EnablesSudoMode;
    use PasswordChallenge;
    use PublicKeyChallenge;

    /**
     * Sends a response that displays the sudo-mode challenge page.
     *
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, ?PublicKeyCredentialRequestOptions $options);

    /**
     * Sends a response indicating that sudo-mode has been enabled.
     *
     * @return mixed
     */
    abstract protected function sendSudoModeEnabledResponse(Request $request);

    /**
     * Sends a response indicating that sudo-mode is currently not required.
     *
     * @return mixed
     */
    abstract protected function sendConfirmationNotRequiredResponse(Request $request);

    /**
     * Display the sudo-mode challenge view.
     *
     * @see static::sendConfirmationNotRequiredResponse()
     * @see static::sendChallengePageResponse()
     *
     * @return mixed
     */
    public function create(Request $request)
    {
        if (! $this->requiresConfirmation($request)) {
            return $this->sendConfirmationNotRequiredResponse($request);
        }

        return $this->sendChallengePageResponse($request, $this->handlePublicKeyChallengeInitialization($request));
    }

    /**
     * Determine whether the user is able to confirm the sudo-mode challenge using their password.
     */
    protected function supportsPasswordBasedConfirmation(Request $request): bool
    {
        return $request->user()->has_password;
    }

    /**
     * Verify the sudo-mode confirmation request.
     *
     * @see static::sendConfirmationNotRequiredResponse()
     * @see static::sendRateLimitedResponse()
     * @see static::sendPasswordChallengeFailedResponse()
     * @see static::sendInvalidPublicKeyChallengeStateResponse()
     * @see static::sendPublicKeyChallengeFailedResponse()
     * @see static::sendSudoModeEnabledResponse()
     *
     * @return mixed
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
     */
    protected function requiresConfirmation(Request $request): bool
    {
        return $request->session()->has(EnsureSudoMode::REQUIRED_AT_KEY);
    }

    /**
     * Determine if the given request is a password based confirmation request.
     */
    protected function isPasswordBasedConfirmationRequest(Request $request): bool
    {
        return $request->has('password') && $this->supportsPasswordBasedConfirmation($request);
    }

    /**
     * Emits an event indicating that sudo-mode was enabled.
     */
    protected function emitSudoModeEnabledEvent(Request $request): void
    {
        Event::dispatch(new SudoModeEnabled($request, $request->user()));
    }

    /**
     * Sends a response indicating that the password challenge has succeeded.
     *
     * @return mixed
     */
    protected function sendPasswordChallengeSuccessfulResponse(Request $request)
    {
        $this->handlePublicKeyChallengeInvalidation($request);

        $this->enableSudoMode($request);
        $this->emitSudoModeEnabledEvent($request);

        return $this->sendSudoModeEnabledResponse($request);
    }

    /**
     * Sends a response indicating that the public key challenge has succeeded.
     *
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
     */
    protected function intendedLocation(Request $request): string
    {
        return $request->session()->pull('url.intended')
            ?? $this->redirectTo
            ?? RouteServiceProvider::HOME
            ?? '/';
    }

    /**
     * Determine the identifier used to track the public key challenge options state.
     */
    protected function publicKeyChallengeOptionsKey(Request $request): string
    {
        return 'laravel-auth::sudo_mode.public_key_challenge_request_options';
    }

    /**
     * Determine the rate limits that apply to the request.
     */
    protected function rateLimits(Request $request): array
    {
        return [
            Limit::perMinute(5)->by('ip::'.$request->ip()),
            Limit::perMinute(5)->by('user_id::'.Auth::id()),
        ];
    }
}
