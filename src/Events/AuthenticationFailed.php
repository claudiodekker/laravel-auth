<?php

namespace ClaudioDekker\LaravelAuth\Events;

use Illuminate\Http\Request;

class AuthenticationFailed
{
    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(
        public Request $request,
        public ?string $username = null
    ) {
        //
    }
}
