<?php

namespace ClaudioDekker\LaravelAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EnsurePreAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        if (! $request->hasSession() || $request->session()->missing('auth.mfa.user_id')) {
            return redirect()->route('login');
        }

        return $next($request);
    }
}
