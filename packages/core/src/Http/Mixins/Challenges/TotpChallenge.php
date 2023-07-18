<?php

namespace ClaudioDekker\LaravelAuth\Http\Mixins\Challenges;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract as Totp;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Timebox;

trait TotpChallenge
{
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the time-based one-time-password challenge has succeeded.
     *
     * @return mixed
     */
    abstract protected function sendTotpChallengeFailedResponse(Request $request);

    /**
     * Sends a response indicating that the time-based one-time-password challenge did not succeed.
     *
     * @return mixed
     */
    abstract protected function sendTotpChallengeSuccessfulResponse(Request $request);

    /**
     * Handle a time-based one-time-password challenge confirmation request.
     *
     * @return mixed
     */
    protected function handleTotpChallengeRequest(Request $request)
    {
        return App::make(Timebox::class)->call(function (Timebox $timebox) use ($request) {
            $this->validateTotpChallengeRequest($request);

            if ($this->isCurrentlyRateLimited($request)) {
                $this->emitLockoutEvent($request);

                return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
            }

            if (! $this->hasValidTotpCode($request)) {
                $this->incrementRateLimitingCounter($request);

                return $this->sendTotpChallengeFailedResponse($request);
            }

            $this->resetRateLimitingCounter($request);
            $timebox->returnEarly();

            return $this->sendTotpChallengeSuccessfulResponse($request);
        }, 300 * 1000);
    }

    /**
     * Validate the time-based one-time-password challenge response.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateTotpChallengeRequest(Request $request): void
    {
        $request->validate([
            'code' => 'required|string',
        ]);
    }

    /**
     * Verify whether the time-based one-time-password is valid for the given secret.
     */
    protected function verifyTotpCode(mixed $userId, string $secret, string $code): bool
    {
        /** @var Totp $authenticator */
        $authenticator = App::make(Totp::class);

        return $authenticator->verify($userId, $secret, $code);
    }

    /**
     * Resolve the User instance that the challenge is for.
     */
    protected function resolveUser(Request $request): Authenticatable
    {
        return $request->user();
    }

    /**
     * Determine whether the request contains a valid time-based one-time-password.
     */
    protected function hasValidTotpCode(Request $request): bool
    {
        $code = $request->input('code');
        $userId = $this->resolveUser($request)->getAuthIdentifier();

        return $this->getTotpSecrets($userId)->contains(function (string $secret) use ($userId, $code) {
            return $this->verifyTotpCode($userId, $secret, $code);
        });
    }

    /**
     * Retrieve all active time-based one-time-password secrets for the given user ID.
     */
    protected function getTotpSecrets(mixed $userId): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', $userId)
            ->where('type', CredentialType::TOTP)
            ->get()
            ->map(fn ($credential) => $credential->secret);
    }
}
