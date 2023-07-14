<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

trait HandlesLogouts
{
    /**
     * Sends a response indicating that the user has been signed out.
     *
     * @return mixed
     */
    abstract protected function sendLoggedOutResponse(Request $request);

    /**
     * Handle a logout request.
     *
     * @return mixed
     */
    protected function handleLogoutRequest(Request $request)
    {
        $this->logout($request);

        return $this->sendLoggedOutResponse($request);
    }

    /**
     * Sign the user out of the application.
     */
    protected function logout(Request $request): void
    {
        Auth::logoutCurrentDevice();

        $request->session()->invalidate();
    }
}
