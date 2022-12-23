<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use App\Models\User;
use ClaudioDekker\LaravelAuth\Events\AccountRecovered;
use ClaudioDekker\LaravelAuth\Events\AccountRecoveryFailed;
use ClaudioDekker\LaravelAuth\Http\Concerns\EmitsAuthenticationEvents;
use ClaudioDekker\LaravelAuth\Http\Concerns\EnablesSudoMode;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\RecoveryCodeManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

abstract class AccountRecoveryChallengeController
{
    use EnablesSudoMode;
    use EmitsAuthenticationEvents;
    use InteractsWithRateLimiting;

    /**
     * Sends a response that displays the account recovery challenge page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $token
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, string $token);

    /**
     * Sends a response indicating that the given recovery link is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidRecoveryLinkResponse(Request $request);

    /**
     * Sends a response indicating that the given recovery code is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidRecoveryCodeResponse(Request $request);

    /**
     * Sends a response indicating that the user's account has been recovered.
     *
     * Typically, you'd want this response to redirect the user to their account's security settings page,
     * where they can adjust whatever is causing them to be unable to authenticate using normal means.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return mixed
     */
    abstract protected function sendAccountRecoveredResponse(Request $request, Authenticatable $user);

    /**
     * Handle an incoming request to view the account recovery challenge page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $token
     * @return mixed
     *
     * @see static::sendAccountRecoveredResponse()
     * @see static::sendChallengePageResponse()
     * @see static::sendInvalidRecoveryLinkResponse()
     */
    public function create(Request $request, string $token)
    {
        if (! $user = $this->resolveUser($request)) {
            return $this->sendInvalidRecoveryLinkResponse($request);
        }

        if (! $this->isValidRecoveryLink($user, $token)) {
            return $this->sendInvalidRecoveryLinkResponse($request);
        }

        if (! $this->hasRecoveryCodes($request, $user)) {
            $this->invalidateRecoveryLink($request, $user);

            return $this->handleAccountRecoveredResponse($request, $user);
        }

        return $this->sendChallengePageResponse($request, $token);
    }

    /**
     * Handle an incoming account recovery challenge response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $token
     * @return mixed
     *
     * @see static::sendAccountRecoveredResponse()
     * @see static::sendInvalidRecoveryCodeResponse()
     * @see static::sendInvalidRecoveryLinkResponse()
     * @see static::sendRateLimitedResponse()
     */
    public function store(Request $request, string $token)
    {
        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitingExpiresInSeconds($request));
        }

        if (! $user = $this->resolveUser($request)) {
            $this->incrementRateLimitingCounter($request);

            return $this->sendInvalidRecoveryLinkResponse($request);
        }

        if (! $this->isValidRecoveryLink($user, $token)) {
            $this->incrementRateLimitingCounter($request);

            return $this->sendInvalidRecoveryLinkResponse($request);
        }

        if (! $this->hasRecoveryCodes($request, $user)) {
            $this->invalidateRecoveryLink($request, $user);

            return $this->handleAccountRecoveredResponse($request, $user);
        }

        if (! $this->hasValidRecoveryCode($request, $user)) {
            $this->incrementRateLimitingCounter($request);
            $this->emitAccountRecoveryFailedEvent($request, $user);

            return $this->sendInvalidRecoveryCodeResponse($request);
        }

        $this->resetRateLimitingCounter($request);
        $this->invalidateRecoveryCode($request, $user);
        $this->invalidateRecoveryLink($request, $user);

        return $this->handleAccountRecoveredResponse($request, $user);
    }

    /**
     * Determines whether the current recovery link is valid.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return bool
     */
    protected function isValidRecoveryLink(Authenticatable $user, string $token): bool
    {
        return Password::getRepository()->exists($user, $token);
    }

    /**
     * Resolves the User instance for which the account is being reset.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function resolveUser(Request $request)
    {
        return User::query()
            ->where('email', $request->input('email'))
            ->first();
    }

    /**
     * Handles the situation where the user has successfully recovered their account.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return mixed
     */
    protected function handleAccountRecoveredResponse(Request $request, Authenticatable $user)
    {
        $this->authenticate($request, $user);
        $this->enableSudoMode($request);
        $this->emitAccountRecoveredEvent($request, $user);

        return $this->sendAccountRecoveredResponse($request, $user);
    }

    /**
     * Authenticate the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function authenticate(Request $request, Authenticatable $user): void
    {
        Auth::login($user);
    }

    /**
     * Determine whether the user has recovery codes.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     */
    protected function hasRecoveryCodes(Request $request, Authenticatable $user): bool
    {
        return (bool) $user->recovery_codes;
    }

    /**
     * Determine whether the user has entered a valid confirmation code.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return bool
     */
    protected function hasValidRecoveryCode(Request $request, Authenticatable $user): bool
    {
        return RecoveryCodeManager::from($user->recovery_codes)->contains($request->input('code'));
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function invalidateRecoveryCode(Request $request, Authenticatable $user): void
    {
        $user->recovery_codes = RecoveryCodeManager::from($user->recovery_codes)
            ->remove($request->input('code'))
            ->toArray();

        $user->save();
    }

    /**
     * Invalidates the recovery link for the given user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function invalidateRecoveryLink(Request $request, Authenticatable $user): void
    {
        Password::getRepository()->delete($user);
    }

    /**
     * Emits an event indicating that the user's account has been recovered.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function emitAccountRecoveredEvent(Request $request, Authenticatable $user): void
    {
        Event::dispatch(new AccountRecovered($request, $user));
    }

    /**
     * Emits an event indicating that an account recovery attempt has failed.
     *
     * This is useful in situations where you want to track failed account recovery attempts,
     * such as detecting the possibility of an user's email account being compromised, to
     * identify the IP address of whoever is attempting to recover, or to provide extra
     * context to the support team in case the user ends up being unable to recover.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function emitAccountRecoveryFailedEvent(Request $request, Authenticatable $user): void
    {
        Event::dispatch(new AccountRecoveryFailed($request, $user));
    }

    /**
     * Get the rate limiting throttle key for the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function throttleKey(Request $request): string
    {
        return Str::lower('account-recovery-challenge|'.$request->ip());
    }
}
