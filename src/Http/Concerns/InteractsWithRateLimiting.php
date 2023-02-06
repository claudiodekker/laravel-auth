<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\RateLimiter;

trait InteractsWithRateLimiting
{
    /**
     * Prepare the identifier used to track the rate limiting state.
     *
     * @param  string  $key
     * @return string
     */
    protected function throttleKey(string $key): string
    {
        return "auth::$key";
    }

    /**
     * Sends a response indicating that the requests have been rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $availableInSeconds
     * @return mixed
     */
    abstract protected function sendRateLimitedResponse(Request $request, int $availableInSeconds);

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
        ];
    }

    /**
     * Determines whether the request is currently rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isCurrentlyRateLimited(Request $request): bool
    {
        return Collection::make($this->rateLimits($request))->contains(function (Limit $limit) {
            return RateLimiter::tooManyAttempts($this->throttleKey($limit->key), $limit->maxAttempts);
        });
    }

    /**
     * Determines the seconds remaining until rate limiting is lifted.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return int
     */
    protected function rateLimitExpiresInSeconds(Request $request): int
    {
        return Collection::make($this->rateLimits($request))
            ->max(fn (Limit $limit) => RateLimiter::availableIn($this->throttleKey($limit->key)));
    }

    /**
     * Increments the rate limiting counter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function incrementRateLimitingCounter(Request $request): void
    {
        Collection::make($this->rateLimits($request))->each(function (Limit $limit) {
            RateLimiter::hit($this->throttleKey($limit->key), $limit->decayMinutes * 60);
        });
    }

    /**
     * Clears the rate limiting counter (if any).
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function resetRateLimitingCounter(Request $request): void
    {
        Collection::make($this->rateLimits($request))
            ->filter(fn (Limit $limit) => $limit->key)
            ->each(fn (Limit $limit) => RateLimiter::clear($this->throttleKey($limit->key)));
    }
}
