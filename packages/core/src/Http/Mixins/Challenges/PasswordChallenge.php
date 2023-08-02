<?php

namespace ClaudioDekker\LaravelAuth\Http\Mixins\Challenges;

use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Timebox;

trait PasswordChallenge
{
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the password challenge did not succeed.
     *
     * @return mixed
     */
    abstract protected function sendPasswordChallengeFailedResponse(Request $request);

    /**
     * Sends a response indicating that the password challenge has succeeded.
     *
     * @return mixed
     */
    abstract protected function sendPasswordChallengeSuccessfulResponse(Request $request);

    /**
     * Handle a password challenge confirmation request.
     *
     * @return mixed
     */
    protected function handlePasswordChallengeRequest(Request $request)
    {
        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
        }

        $this->incrementRateLimitingCounter($request);

        return App::make(Timebox::class)->call(function (Timebox $timebox) use ($request) {
            $this->validatePasswordChallengeRequest($request);

            if (! $this->hasValidPassword($request)) {
                return $this->sendPasswordChallengeFailedResponse($request);
            }

            $this->resetRateLimitingCounter($request);
            $timebox->returnEarly();

            return $this->sendPasswordChallengeSuccessfulResponse($request);
        }, 300 * 1000);
    }

    /**
     * Validate the password challenge confirmation request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasswordChallengeRequest(Request $request): void
    {
        $request->validate([
            'password' => 'required|string',
        ]);
    }

    /**
     * Determine whether the provided password matches the current user.
     */
    protected function hasValidPassword(Request $request): bool
    {
        return Auth::validate([
            'id' => Auth::id(),
            'password' => $request->input('password'),
        ]);
    }
}
