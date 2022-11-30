<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

trait HandlesLogouts
{
    /**
     * Sign the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function logout(Request $request): void
    {
        Auth::logoutCurrentDevice();

        $request->session()->invalidate();
    }
}
