<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsAuthenticatedEvent;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsLockoutEvent;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallengeFailed;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\PublicKeyChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\Challenges\TotpChallenge;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;

abstract class MultiFactorChallengeController
{
    use EmailBased;
    use EmitsAuthenticatedEvent;
    use EmitsLockoutEvent;
    use EnablesSudoMode;
    use PublicKeyChallenge;
    use TotpChallenge;

    /**
     * Sends a response that displays the multi-factor challenge page.
     *
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, ?PublicKeyCredentialRequestOptions $options, Collection $availableCredentialTypes);

    /**
     * Sends a response indicating that the multi-factor challenge has succeeded.
     */
    protected function handleChallengeSuccessfulResponse(Request $request): mixed
    {
        $user = $this->authenticate($request);

        $intendedUrl = $this->intendedLocation($request);
        $this->clearMultiFactorAuthenticationDetails($request);
        $this->enableSudoMode($request);
        $this->emitAuthenticatedEvent($request, $user);

        return $this->sendAuthenticatedResponse($request, $user, $intendedUrl);
    }

    /**
     * Sends a response indicating that the user has been successfully authenticated.
     *
     * @return mixed
     */
    abstract protected function sendAuthenticatedResponse(Request $request, Authenticatable $user, string $intendedUrl);

    /**
     * Sends a response indicating that the multi-factor challenge has failed.
     *
     * This can be for a large number of reasons, including (but not limited to) a malformed request,
     * a non-existent credential, an invalid signature or confirmation code etc.
     *
     * @return mixed
     */
    abstract protected function sendChallengeFailedResponse(Request $request);

    /**
     * Handle an incoming request to view the multi-factor challenge page.
     *
     * @see static::sendAuthenticatedResponse()
     * @see static::sendChallengePageResponse()
     *
     * @return mixed
     */
    public function create(Request $request)
    {
        $credentials = $this->getMultiFactorCredentials($request);

        if ($credentials->isEmpty()) {
            return $this->handleChallengeSuccessfulResponse($request);
        }

        $availableTypes = $this->filterAvailableCredentialTypes($credentials);
        $publicKeyCredentials = $this->filterPublicKeyCredentials($credentials);
        $options = $this->initializePublicKeyChallenge($request, $publicKeyCredentials);

        return $this->sendChallengePageResponse($request, $options, $availableTypes);
    }

    /**
     * Handle an incoming multi-factor challenge confirmation request.
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendInvalidPublicKeyChallengeStateResponse()
     * @see static::sendChallengeFailedResponse()
     * @see static::sendAuthenticatedResponse()
     *
     * @return mixed
     */
    public function store(Request $request)
    {
        if (! $this->isPublicKeyConfirmationRequest($request)) {
            return $this->handleTotpChallengeRequest($request);
        }

        return $this->handlePublicKeyChallengeRequest($request);
    }

    /**
     * Determine if the given request is a security key based confirmation request.
     */
    protected function isPublicKeyConfirmationRequest(Request $request): bool
    {
        return $request->has('credential');
    }

    /**
     * Emits an event indicating that the multi-factor challenge attempt has failed.
     */
    protected function emitMultiFactorChallengeFailedEvent(Request $request, Authenticatable $user, CredentialType $type): void
    {
        Event::dispatch(new MultiFactorChallengeFailed($request, $user, $type));
    }

    /**
     * Sends a response indicating that the public key challenge did not succeed.
     *
     * @return mixed
     */
    protected function sendPublicKeyChallengeFailedResponse(Request $request)
    {
        $this->emitMultiFactorChallengeFailedEvent($request, $this->resolveUser($request), CredentialType::PUBLIC_KEY);

        return $this->sendChallengeFailedResponse($request);
    }

    /**
     * Sends a response indicating that the time-based one-time-password challenge did not succeed.
     *
     * @return mixed
     */
    protected function sendTotpChallengeFailedResponse(Request $request)
    {
        $this->emitMultiFactorChallengeFailedEvent($request, $this->resolveUser($request), CredentialType::TOTP);

        return $this->sendChallengeFailedResponse($request);
    }

    /**
     * Sends a response indicating that the public key challenge has succeeded.
     *
     * @return mixed
     */
    protected function sendPublicKeyChallengeSuccessfulResponse(Request $request)
    {
        return $this->handleChallengeSuccessfulResponse($request);
    }

    /**
     * Sends a response indicating that the time-based one-time-password challenge has succeeded.
     *
     * @return mixed
     */
    protected function sendTotpChallengeSuccessfulResponse(Request $request)
    {
        return $this->handleChallengeSuccessfulResponse($request);
    }

    /**
     * Retrieve all active multi-factor credentials for the authenticating user.
     */
    protected function getMultiFactorCredentials(Request $request): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', $request->session()->get('auth.mfa.user_id'))
            ->get();
    }

    /**
     * Filter and prepare all public key credentials for the given multi-factor credentials.
     */
    protected function filterPublicKeyCredentials(Collection $credentials): Collection
    {
        return $credentials->where('type', CredentialType::PUBLIC_KEY)
            ->map(fn ($credential) => CredentialAttributes::fromJson($credential->secret));
    }

    /**
     * Filter all unique multi-factor credential types for the given credentials.
     */
    protected function filterAvailableCredentialTypes(Collection $credentials): Collection
    {
        return $credentials->pluck('type')
            ->unique()
            ->values();
    }

    /**
     * Resolve the User instance that is being authenticated.
     */
    protected function resolveUser(Request $request): Authenticatable
    {
        return Auth::guard()->getProvider()->retrieveById(
            $request->session()->get('auth.mfa.user_id')
        );
    }

    /**
     * Fully authenticate the user into the application.
     */
    protected function authenticate(Request $request): Authenticatable
    {
        return Auth::loginUsingId(
            $request->session()->get('auth.mfa.user_id'),
            $request->session()->get('auth.mfa.remember')
        );
    }

    /**
     * Resolve the URL that the user intended to visit prior to authentication.
     */
    protected function intendedLocation(Request $request): string
    {
        return $request->session()->get('auth.mfa.intended_location');
    }

    /**
     * Clear the multi-factor specific authentication details set during login.
     */
    protected function clearMultiFactorAuthenticationDetails(Request $request): void
    {
        $request->session()->remove('auth.mfa.intended_location');
        $request->session()->remove('auth.mfa.remember');
        $request->session()->remove('auth.mfa.user_id');
    }

    /**
     * Determine the rate limits that apply to the request.
     */
    protected function rateLimits(Request $request): array
    {
        return [
            Limit::perMinute(250),
            Limit::perMinute(5)->by('ip::'.$request->ip()),
            Limit::perMinute(5)->by('user_id::'.$request->session()->get('auth.mfa.user_id')),
        ];
    }
}
