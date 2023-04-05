<?php

namespace ClaudioDekker\LaravelAuth\Events\Mixins;

use ClaudioDekker\LaravelAuth\Events\Authenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;

trait EmitsAuthenticatedEvent
{
    /**
     * Emits an event indicating that the user was fully authenticated.
     */
    protected function emitAuthenticatedEvent(Request $request, Authenticatable $user): void
    {
        Event::dispatch(new Authenticated($request, $user));
    }
}
