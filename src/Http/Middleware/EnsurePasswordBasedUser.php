<?php

namespace ClaudioDekker\LaravelAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EnsurePasswordBasedUser
{
    /**
     * Handle an incoming request.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        abort_if(! $request->hasSession(), 501);
        abort_if(! $request->user(), 401);
        abort_if(! $request->user()->has_password, 403);

        return $next($request);
    }
}
