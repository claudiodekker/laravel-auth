<?php

namespace ClaudioDekker\LaravelAuth\Http\Modifiers;

use Illuminate\Http\Request;

trait WithoutRateLimiting
{
    /**
     * Determines whether the request is currently rate limited.
     */
    protected function isCurrentlyRateLimited(Request $request): bool
    {
        return false;
    }

    /**
     * Increments the rate limiting counter.
     */
    protected function incrementRateLimitingCounter(Request $request): void
    {
        //
    }

    /**
     * Sends a response indicating that the user's requests have been rate limited.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function sendRateLimitedResponse(Request $request, int $availableInSeconds): void
    {
        //
    }
}
