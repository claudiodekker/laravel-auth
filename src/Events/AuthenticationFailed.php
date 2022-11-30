<?php

namespace ClaudioDekker\LaravelAuth\Events;

use Illuminate\Http\Request;

class AuthenticationFailed
{
    /**
     * Create a new event instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string|null  $username
     * @return void
     */
    public function __construct(
        public Request $request,
        public ?string $username = null
    ) {
        //
    }
}
