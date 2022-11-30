<?php

namespace ClaudioDekker\LaravelAuth\Http\Traits;

use Illuminate\Http\Request;

trait WithoutRateLimiting
{
    /**
     * Determines whether the request is currently rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isCurrentlyRateLimited(Request $request): bool
    {
        return false;
    }

    /**
     * Increments the rate limiting counter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function incrementRateLimitingCounter(Request $request): void
    {
        //
    }

    /**
     * Sends a response indicating that the user's requests have been rate limited.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $availableInSeconds
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function sendRateLimitedResponse(Request $request, int $availableInSeconds): void
    {
        //
    }
}
