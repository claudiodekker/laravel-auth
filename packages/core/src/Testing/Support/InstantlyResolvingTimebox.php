<?php

namespace ClaudioDekker\LaravelAuth\Testing\Support;

use Illuminate\Support\Timebox;

class InstantlyResolvingTimebox extends Timebox
{
    /**
     * Intended for testing purposes only, not for production use.
     *
     * @see Timebox::call()
     */
    public function call(callable $callback, int $microseconds)
    {
        return $callback($this);
    }
}
