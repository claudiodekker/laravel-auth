<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Login;

use App\Models\User;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsLockoutEvent;
use ClaudioDekker\LaravelAuth\Events\MultiFactorChallenged;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;

trait PasswordBasedAuthentication
{
    use EmitsLockoutEvent;
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the user needs to confirm a 2FA challenge.
     *
     * @return mixed
     */
    abstract protected function sendMultiFactorChallengeResponse(Request $request, CredentialType $preferredMethod);

    /**
     * Handle a password based authentication request.
     *
     * @return mixed
     */
    protected function handlePasswordBasedAuthentication(Request $request)
    {
        $this->validatePasswordBasedRequest($request);

        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
        }

        if (! $user = $this->validatePasswordBasedCredentials($request)) {
            $this->incrementRateLimitingCounter($request);
            $this->emitAuthenticationFailedEvent($request);

            return $this->sendAuthenticationFailedResponse($request);
        }

        $this->sanitizeMultiFactorSessionState($request);

        $credentials = $this->fetchMultiFactorCredentials($user);
        if ($credentials->isEmpty()) {
            $this->resetRateLimitingCounter($request);
            $this->authenticate($user, $this->isRememberingUser($request));
            $this->enableSudoMode($request);
            $this->emitAuthenticatedEvent($request, $user);

            return $this->sendAuthenticatedResponse($request, $user);
        }

        $preferredMethod = $this->determinePreferredMultiFactorMethod($user, $credentials);
        $this->prepareMultiFactorAuthenticationDetails($request, $user);
        $this->emitMultiFactorChallengedEvent($request, $user);

        return $this->sendMultiFactorChallengeResponse($request, $preferredMethod);
    }

    /**
     * Validate the password based authentication request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasswordBasedRequest(Request $request): void
    {
        $request->validate([
            ...$this->authenticationValidationRules(),
            'password' => 'required|string',
        ]);
    }

    /**
     * Resolve the User that is being authenticated.
     */
    protected function resolvePasswordBasedUser(Request $request): ?Authenticatable
    {
        /** @var \Illuminate\Database\Eloquent\Builder $query */
        $query = User::query();

        return $query
            ->where('has_password', true)
            ->where($this->usernameField(), $request->input($this->usernameField()))
            ->first();
    }

    /**
     * Validates the username and password combination.
     */
    protected function validatePasswordBasedCredentials(Request $request): ?Authenticatable
    {
        if (! $user = $this->resolvePasswordBasedUser($request)) {
            return null;
        }

        if (! Hash::check($request->input('password'), $user->getAuthPassword())) {
            return null;
        }

        return $user;
    }

    /**
     * Clears any multi-factor challenge details (pending from a previous login attempt) from the session.
     *
     * This prevents state carry-over attacks where an attacker can manipulate the order of requests as such that
     * they can confirm a 2FA challenge intended for their account, while pre-authenticated as their victim.
     */
    protected function sanitizeMultiFactorSessionState(Request $request): void
    {
        $request->session()->forget('laravel-auth::public_key_challenge_request_options');
    }

    /**
     * Retrieve all multi-factor credentials for the given user.
     */
    protected function fetchMultiFactorCredentials(Authenticatable $user): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', $user->getAuthIdentifier())
            ->get();
    }

    /**
     * Determines the preferred multi-factor authentication method.
     */
    protected function determinePreferredMultiFactorMethod(Authenticatable $user, Collection $credentials): CredentialType
    {
        if ($credentials->pluck('type')->contains(CredentialType::PUBLIC_KEY)) {
            return CredentialType::PUBLIC_KEY;
        }

        return CredentialType::TOTP;
    }

    /**
     * Prepares the details necessary for multi-factor authentication.
     */
    protected function prepareMultiFactorAuthenticationDetails(Request $request, Authenticatable $user): void
    {
        $request->session()->put('auth.mfa.intended_location', $this->intendedLocation($request));
        $request->session()->put('auth.mfa.remember', $this->isRememberingUser($request));
        $request->session()->put('auth.mfa.user_id', $user->getAuthIdentifier());
    }

    /**
     * Emits an event indicating the user received a multi-factor authentication challenge.
     */
    protected function emitMultiFactorChallengedEvent(Request $request, Authenticatable $user): void
    {
        Event::dispatch(new MultiFactorChallenged($request, $user));
    }
}
