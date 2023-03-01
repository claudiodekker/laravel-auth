<?php

namespace ClaudioDekker\LaravelAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class RecoveryCodesGenerated
{
    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(
        public Request $request,
        public Authenticatable $user
    ) {
        //
    }
}
