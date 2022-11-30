<?php

namespace ClaudioDekker\LaravelAuth\Events;

use ClaudioDekker\LaravelAuth\CredentialType;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class MultiFactorChallengeFailed
{
    /**
     * Create a new event instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  \ClaudioDekker\LaravelAuth\CredentialType  $type
     * @return void
     */
    public function __construct(
        public Request $request,
        public Authenticatable $user,
        public CredentialType $type
    ) {
        //
    }
}
