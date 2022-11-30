<?php

namespace ClaudioDekker\LaravelAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class MultiFactorChallenged
{
    /**
     * Create a new event instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function __construct(
        public Request $request,
        public Authenticatable $user
    ) {
        //
    }
}
