<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

trait InteractsWithRateLimiting
{
    /**
     * Get the rate limiting throttle key for the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    abstract protected function throttleKey(Request $request): string;

    /**
     * Sends a response indicating that the requests have been rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $availableInSeconds
     * @return mixed
     */
    abstract protected function sendRateLimitedResponse(Request $request, int $availableInSeconds);

    /**
     * The number of requests per minute that aren't rate limited.
     *
     * @return int
     */
    protected function maxAttempts(): int
    {
        return 5;
    }

    /**
     * Determines whether the request is currently rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isCurrentlyRateLimited(Request $request): bool
    {
        return RateLimiter::tooManyAttempts($this->throttleKey($request), $this->maxAttempts());
    }

    /**
     * Determines the seconds remaining until rate limiting is lifted.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return int
     */
    protected function rateLimitExpiresInSeconds(Request $request): int
    {
        return RateLimiter::availableIn($this->throttleKey($request));
    }

    /**
     * Increments the rate limiting counter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function incrementRateLimitingCounter(Request $request): void
    {
        RateLimiter::hit($this->throttleKey($request));
    }

    /**
     * Clears the rate limiting counter (if any).
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function resetRateLimitingCounter(Request $request): void
    {
        RateLimiter::clear($this->throttleKey($request));
    }
}
