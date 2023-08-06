<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers;

use App\Notifications\AccountRecoveryNotification;
use ClaudioDekker\LaravelAuth\Events\Mixins\EmitsLockoutEvent;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\Http\Modifiers\EmailBased;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Timebox;

abstract class RecoveryRequestController
{
    use EmailBased;
    use InteractsWithRateLimiting;
    use EmitsLockoutEvent;

    /**
     * Handles the situation in which account recovery has already been requested.
     *
     * NOTE: To prevent malicious visitors from probing the system for valid email addresses, this method should not
     * indicate that recovery has already been requested. Instead, it should always return the same response.
     *
     * @return mixed
     */
    abstract protected function sendRecoveryAlreadyRequestedResponse(Request $request, Authenticatable $user);

    /**
     * Handles the situation in which the user has not been found.
     *
     * NOTE: To prevent malicious visitors from probing the system for valid email addresses, this method should not
     * indicate that the account was not found. Instead, it should always return the same response.
     *
     * @return mixed
     */
    abstract protected function sendNoSuchUserResponse(Request $request);

    /**
     * Sends a response indicating that the recovery link has been sent.
     *
     * NOTE: To prevent malicious visitors from probing the system for valid email addresses, this method (by default)
     * is also called when the user has not been found, and when the recovery has already been requested.
     *
     * @see static::sendNoSuchUserResponse()
     * @see static::sendRecoveryAlreadyRequestedResponse()
     *
     * @return mixed
     */
    abstract public function sendRecoveryLinkSentResponse(Request $request);

    /**
     * Handle an incoming request to view the account recovery page.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function create(Request $request)
    {
        return view('auth.recover-account');
    }

    /**
     * Handle an incoming request to receive an account recovery link.
     *
     * @see static::sendRateLimitedResponse()
     * @see static::sendNoSuchUserResponse()
     * @see static::sendRecoveryAlreadyRequestedResponse()
     * @see static::sendRecoveryLinkSentResponse()
     *
     * @return mixed
     */
    public function store(Request $request)
    {
        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
        }

        $this->incrementRateLimitingCounter($request);

        return App::make(Timebox::class)->call(function () use ($request) {
            $this->validateRecoveryRequest($request);

            if (! $user = $this->getUser($request)) {
                return $this->sendNoSuchUserResponse($request);
            }

            if ($this->recoveryRecentlyRequested($user)) {
                return $this->sendRecoveryAlreadyRequestedResponse($request, $user);
            }

            $token = $this->createRecoveryToken($user);
            $this->sendRecoveryLinkNotification($request, $user, $token);

            return $this->sendRecoveryLinkSentResponse($request);
        }, 300 * 1000);
    }

    /**
     * Validate the account recovery request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateRecoveryRequest(Request $request): void
    {
        $request->validate([
            $this->usernameField() => ['required', ...$this->usernameValidationRules()],
        ]);
    }

    /**
     * Resolve the User that should be recovered.
     */
    protected function getUser(Request $request): ?CanResetPassword
    {
        /** @var \Illuminate\Database\Eloquent\Builder $query */
        $query = LaravelAuth::userModel()::query();

        return $query
            ->where($this->usernameField(), $request->input($this->usernameField()))
            ->first();
    }

    /**
     * Determines whether the given user has already requested a recovery link recently.
     */
    protected function recoveryRecentlyRequested(CanResetPassword $user): bool
    {
        return Password::getRepository()->recentlyCreatedToken($user);
    }

    /**
     * Create a new recovery token for the given user.
     */
    protected function createRecoveryToken(CanResetPassword $user): string
    {
        return Password::getRepository()->create($user);
    }

    /**
     * Sends the recovery link notification to the given user.
     *
     * @param  \Illuminate\Contracts\Auth\CanResetPassword  $user
     */
    protected function sendRecoveryLinkNotification(Request $request, mixed $user, string $token): void
    {
        $user->notify(new AccountRecoveryNotification($token));
    }
}
