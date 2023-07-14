<?php

namespace ClaudioDekker\LaravelAuth\Http\Mixins;

use ClaudioDekker\LaravelAuth\Http\Middleware\EnsureSudoMode;
use Illuminate\Http\Request;

trait EnablesSudoMode
{
    /**
     * Enables sudo-mode for the current user.
     */
    protected function enableSudoMode(Request $request): void
    {
        $request->session()->put(EnsureSudoMode::CONFIRMED_AT_KEY, now()->unix());
        $request->session()->forget(EnsureSudoMode::REQUIRED_AT_KEY);
    }
}
