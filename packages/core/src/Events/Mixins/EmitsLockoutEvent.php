<?php

namespace ClaudioDekker\LaravelAuth\Events\Mixins;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;

trait EmitsLockoutEvent
{
    /**
     * Emits an event indicating that the user has been locked out for a while.
     */
    protected function emitLockoutEvent(Request $request): void
    {
        Event::dispatch(new Lockout($request));
    }
}
