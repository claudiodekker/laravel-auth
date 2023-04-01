<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

trait InteractsWithRateLimiting
{
    /**
     * Get the rate limiting throttle key for the request.
     */
    abstract protected function throttleKey(Request $request): string;

    /**
     * Sends a response indicating that the requests have been rate limited.
     *
     * @return mixed
     */
    abstract protected function sendRateLimitedResponse(Request $request, int $availableInSeconds);

    /**
     * The number of requests per minute that aren't rate limited.
     */
    protected function maxAttempts(): int
    {
        return 5;
    }

    /**
     * Determines whether the request is currently rate limited.
     */
    protected function isCurrentlyRateLimited(Request $request): bool
    {
        return RateLimiter::tooManyAttempts($this->throttleKey($request), $this->maxAttempts());
    }

    /**
     * Determines the seconds remaining until rate limiting is lifted.
     */
    protected function rateLimitingExpiresInSeconds(Request $request): int
    {
        return RateLimiter::availableIn($this->throttleKey($request));
    }

    /**
     * Increments the rate limiting counter.
     */
    protected function incrementRateLimitingCounter(Request $request): void
    {
        RateLimiter::hit($this->throttleKey($request));
    }

    /**
     * Clears the rate limiting counter (if any).
     */
    protected function resetRateLimitingCounter(Request $request): void
    {
        RateLimiter::clear($this->throttleKey($request));
    }
}
