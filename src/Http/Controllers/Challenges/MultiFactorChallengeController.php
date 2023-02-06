<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use ClaudioDekker\LaravelAuth\CredentialType;
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

abstract class MultiFactorChallengeController
{
    use EmailBased;
    use EnablesSudoMode;
    use PublicKeyChallenge;
    use TotpChallenge;

    /**
     * Sends a response that displays the multi-factor challenge page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions|null  $options
     * @param  \Illuminate\Support\Collection  $availableCredentialTypes
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, PublicKeyCredentialRequestOptions|null $options, Collection $availableCredentialTypes);

    /**
     * Sends a response indicating that the multi-factor challenge has succeeded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
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
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $intendedUrl
     * @return mixed
     */
    abstract protected function sendAuthenticatedResponse(Request $request, Authenticatable $user, string $intendedUrl);

    /**
     * Sends a response indicating that the multi-factor challenge has failed.
     *
     * This can be for a large number of reasons, including (but not limited to) a malformed request,
     * a non-existent credential, an invalid signature or confirmation code etc.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendChallengeFailedResponse(Request $request);

    /**
     * Handle an incoming request to view the multi-factor challenge page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendAuthenticatedResponse()
     * @see static::sendChallengePageResponse()
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
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendInvalidPublicKeyChallengeStateResponse()
     * @see static::sendChallengeFailedResponse()
     * @see static::sendAuthenticatedResponse()
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
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isPublicKeyConfirmationRequest(Request $request): bool
    {
        return $request->has('credential');
    }

    /**
     * Sends a response indicating that the public key challenge did not succeed.
     *
     * @param  \Illuminate\Http\Request  $request
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
     * @param  \Illuminate\Http\Request  $request
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
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function sendPublicKeyChallengeSuccessfulResponse(Request $request)
    {
        return $this->handleChallengeSuccessfulResponse($request);
    }

    /**
     * Sends a response indicating that the time-based one-time-password challenge has succeeded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function sendTotpChallengeSuccessfulResponse(Request $request)
    {
        return $this->handleChallengeSuccessfulResponse($request);
    }

    /**
     * Retrieve all active multi-factor credentials for the authenticating user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Support\Collection
     */
    protected function getMultiFactorCredentials(Request $request): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', $request->session()->get('auth.mfa.user_id'))
            ->get();
    }

    /**
     * Filter and prepare all public key credentials for the given multi-factor credentials.
     *
     * @param  \Illuminate\Support\Collection  $credentials
     * @return \Illuminate\Support\Collection
     */
    protected function filterPublicKeyCredentials(Collection $credentials): Collection
    {
        return $credentials->where('type', CredentialType::PUBLIC_KEY)
            ->map(fn ($credential) => CredentialAttributes::fromJson($credential->secret));
    }

    /**
     * Filter all unique multi-factor credential types for the given credentials.
     *
     * @param  \Illuminate\Support\Collection  $credentials
     * @return \Illuminate\Support\Collection
     */
    protected function filterAvailableCredentialTypes(Collection $credentials): Collection
    {
        return $credentials->pluck('type')
            ->unique()
            ->values();
    }

    /**
     * Resolve the User instance that is being authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function resolveUser(Request $request): Authenticatable
    {
        return Auth::guard()->getProvider()->retrieveById(
            $request->session()->get('auth.mfa.user_id')
        );
    }

    /**
     * Fully authenticate the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\Auth\Authenticatable
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
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function intendedLocation(Request $request): string
    {
        return $request->session()->get('auth.mfa.intended_location');
    }

    /**
     * Clear the multi-factor specific authentication details set during login.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function clearMultiFactorAuthenticationDetails(Request $request): void
    {
        $request->session()->remove('auth.mfa.intended_location');
        $request->session()->remove('auth.mfa.remember');
        $request->session()->remove('auth.mfa.user_id');
    }

    /**
     * Determine the rate limits that apply to the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
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
