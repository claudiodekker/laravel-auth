<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Challenges;

use ClaudioDekker\LaravelAuth\Events\AccountRecoveryFailed;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsLockoutEvent;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\RecoveryCodeManager;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;

abstract class RecoveryChallengeController
{
    use EmitsLockoutEvent;
    use InteractsWithRateLimiting;

    /**
     * Sends a response that displays the account recovery challenge page.
     *
     * @return mixed
     */
    abstract protected function sendChallengePageResponse(Request $request, string $token);

    /**
     * Sends a response indicating that the given recovery link is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidRecoveryLinkResponse(Request $request);

    /**
     * Sends a response indicating that the given recovery code is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidRecoveryCodeResponse(Request $request);

    /**
     * Sends a response indicating that recovery mode has been enabled for the given user.
     *
     * @return mixed
     */
    abstract protected function sendRecoveryModeEnabledResponse(Request $request, Authenticatable $user);

    /**
     * Handle an incoming request to view the account recovery challenge page.
     *
     * @return mixed
     *
     * @see static::sendInvalidRecoveryLinkResponse()
     * @see static::sendChallengePageResponse()
     * @see static::sendRecoveryModeEnabledResponse()
     */
    public function create(Request $request, string $token)
    {
        $this->incrementRateLimitingCounter($request);

        return App::make(Timebox::class)->call(function (Timebox $timebox) use ($request, $token) {
            if (! $user = $this->resolveUser($request)) {
                return $this->sendInvalidRecoveryLinkResponse($request);
            }

            if (! $this->isValidRecoveryLink($user, $token)) {
                return $this->sendInvalidRecoveryLinkResponse($request);
            }

            $timebox->returnEarly();

            if (! $this->hasRecoveryCodes($request, $user)) {
                $this->invalidateRecoveryLink($request, $user);
                $this->enableRecoveryMode($request, $user);
                $this->resetRateLimitingCounter($request);

                return $this->sendRecoveryModeEnabledResponse($request, $user);
            }

            return $this->sendChallengePageResponse($request, $token);
        }, 300 * 1000);
    }

    /**
     * Handle an incoming account recovery challenge response.
     *
     * @return mixed
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendInvalidRecoveryLinkResponse()
     * @see static::sendInvalidRecoveryCodeResponse()
     * @see static::sendRecoveryModeEnabledResponse()
     */
    public function store(Request $request, string $token)
    {
        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
        }

        $this->incrementRateLimitingCounter($request);

        return App::make(Timebox::class)->call(function (Timebox $timebox) use ($request, $token) {
            if (! $user = $this->resolveUser($request)) {
                return $this->sendInvalidRecoveryLinkResponse($request);
            }

            if (! $this->isValidRecoveryLink($user, $token)) {
                return $this->sendInvalidRecoveryLinkResponse($request);
            }

            if (! $this->hasRecoveryCodes($request, $user)) {
                $this->invalidateRecoveryLink($request, $user);
                $this->enableRecoveryMode($request, $user);
                $this->resetRateLimitingCounter($request);
                $timebox->returnEarly();

                return $this->sendRecoveryModeEnabledResponse($request, $user);
            }

            if (! $this->hasValidRecoveryCode($request, $user)) {
                $this->emitAccountRecoveryFailedEvent($request, $user);

                return $this->sendInvalidRecoveryCodeResponse($request);
            }

            $this->invalidateRecoveryCode($request, $user);
            $this->invalidateRecoveryLink($request, $user);
            $this->enableRecoveryMode($request, $user);
            $this->resetRateLimitingCounter($request);
            $timebox->returnEarly();

            return $this->sendRecoveryModeEnabledResponse($request, $user);
        }, 300 * 1000);
    }

    /**
     * Determines whether the current recovery link is valid.
     */
    protected function isValidRecoveryLink(Authenticatable $user, string $token): bool
    {
        return Password::getRepository()->exists($user, $token);
    }

    /**
     * Resolves the User instance for which the account is being reset.
     */
    protected function resolveUser(Request $request): ?Authenticatable
    {
        /** @var \Illuminate\Database\Eloquent\Builder $query */
        $query = LaravelAuth::userModel()::query();

        return $query
            ->where('email', $request->input('email'))
            ->first();
    }

    /**
     * Determine whether the user has recovery codes.
     */
    protected function hasRecoveryCodes(Request $request, Authenticatable $user): bool
    {
        return (bool) $user->recovery_codes;
    }

    /**
     * Determine whether the user has entered a valid confirmation code.
     */
    protected function hasValidRecoveryCode(Request $request, Authenticatable $user): bool
    {
        return RecoveryCodeManager::from($user->recovery_codes)->contains($request->input('code'));
    }

    /**
     * Invalidates the recovery code for the given user.
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
     */
    protected function invalidateRecoveryLink(Request $request, Authenticatable $user): void
    {
        Password::getRepository()->delete($user);
    }

    /**
     * Emits an event indicating that an account recovery attempt has failed.
     *
     * This is useful in situations where you want to track failed account recovery attempts,
     * such as detecting the possibility of an user's email account being compromised, to
     * identify the IP address of whoever is attempting to recover, or to provide extra
     * context to the support team in case the user ends up being unable to recover.
     */
    protected function emitAccountRecoveryFailedEvent(Request $request, Authenticatable $user): void
    {
        Event::dispatch(new AccountRecoveryFailed($request, $user));
    }

    /**
     * Enables recovery mode for the given user.
     */
    protected function enableRecoveryMode(Request $request, Authenticatable $user): void
    {
        $request->session()->put('auth.recovery_mode.user_id', $user->getAuthIdentifier());
        $request->session()->put('auth.recovery_mode.enabled_at', now());
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

        if ($request->has('email')) {
            $limits[] = Limit::perMinute(5)->by('email::'.Str::transliterate(Str::lower($request->input('email'))));
        }

        return $limits;
    }
}
