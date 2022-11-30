<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Registration;

use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;

trait PasswordBasedRegistration
{
    /**
     * Handle a password based registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function handlePasswordBasedRegistration(Request $request)
    {
        $this->validatePasswordBasedRequest($request);

        $user = $this->createPasswordBasedUser($request);

        $this->emitRegisteredEvent($user);
        $this->sendEmailVerificationNotification($user);
        $this->authenticate($user);
        $this->enableSudoMode($request);

        return $this->sendRegisteredResponse($request, $user);
    }

    /**
     * Validate a password based user registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
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
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function createPasswordBasedUser(Request $request): Authenticatable
    {
        return User::create([
            'email' => $request->input('email'),
            $this->usernameField() => $request->input($this->usernameField()),
            'name' => $request->name,
            'password' => Hash::make($request->password),
            'has_password' => true,
        ]);
    }
}
