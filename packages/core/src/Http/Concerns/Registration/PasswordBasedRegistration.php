<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Registration;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Timebox;
use Illuminate\Validation\Rules\Password;

trait PasswordBasedRegistration
{
    /**
     * Handle a password based registration request.
     *
     * @return mixed
     */
    protected function handlePasswordBasedRegistrationRequest(Request $request)
    {
        return App::make(Timebox::class)->call(function (Timebox $timebox) use ($request) {
            $this->validatePasswordBasedRequest($request);

            $user = $this->createPasswordBasedUser($request);

            $this->emitRegisteredEvent($user);
            $this->sendEmailVerificationNotification($user);
            $this->authenticate($user);
            $this->enableSudoMode($request);
            $timebox->returnEarly();

            return $this->sendRegisteredResponse($request, $user);
        }, 300 * 1000);
    }

    /**
     * Validate a password based user registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasswordBasedRequest(Request $request): void
    {
        $request->validate([
            ...$this->registrationValidationRules(),
            'name' => ['required', 'string', 'max:255'],
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);
    }

    /**
     * Create a password based user account using the given details.
     */
    protected function createPasswordBasedUser(Request $request): Authenticatable
    {
        /** @var \Illuminate\Database\Eloquent\Builder $query */
        $query = LaravelAuth::userModel()::query();

        return $query->create([
            'email' => $request->input('email'),
            $this->usernameField() => $request->input($this->usernameField()),
            'name' => $request->name,
            'password' => Hash::make($request->password),
            'has_password' => true,
        ]);
    }
}
