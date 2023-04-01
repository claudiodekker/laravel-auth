<?php

namespace ClaudioDekker\LaravelAuth\Http\Middleware;

use ClaudioDekker\LaravelAuth\Events\SudoModeChallenged;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;

class EnsureSudoMode
{
    /**
     * The session key used to track if and when sudo-mode has been enabled.
     *
     * @var string
     */
    public const CONFIRMED_AT_KEY = 'auth.sudo_mode_confirmed_at';

    /**
     * The session key used to indicate that the sudo-mode confirmation has been requested.
     *
     * @var string
     */
    public const REQUIRED_AT_KEY = 'auth.sudo_mode_required_at';

    /**
     * Handle an incoming request.
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function handle(Request $request, Closure $next)
    {
        abort_if(! $request->hasSession(), 501);

        $timestamp = $request->session()->get(self::CONFIRMED_AT_KEY, 0);

        if (Carbon::parse($timestamp)->diffInSeconds() < config('laravel-auth.sudo_mode_duration', 900)) {
            $request->session()->put(self::CONFIRMED_AT_KEY, Carbon::now()->unix());

            return $next($request);
        }

        Event::dispatch(new SudoModeChallenged($request, $request->user()));

        $request->session()->forget(self::CONFIRMED_AT_KEY);
        $request->session()->put(self::REQUIRED_AT_KEY, Carbon::now()->unix());

        return $request->expectsJson()
            ? response()->json(['message' => 'Sudo-mode required.'], 403)
            : redirect()->guest(route('auth.sudo_mode'));
    }
}
