<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Settings;

use ClaudioDekker\LaravelAuth\Events\PasswordChanged;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;

abstract class ChangePasswordController
{
    /**
     * Send a response indicating that the user's password has been changed.
     *
     * @return mixed
     */
    abstract protected function sendPasswordChangedResponse(Request $request);

    /**
     * Change the current user's password.
     *
     * @see static::sendPasswordChangedResponse()
     *
     * @return mixed
     */
    public function update(Request $request)
    {
        $this->validatePasswordChangeRequest($request);

        $user = $request->user();

        $this->updateUserPassword($user, $request->input('new_password'));
        $this->emitPasswordChangedEvent($user);

        return $this->sendPasswordChangedResponse($request);
    }

    /**
     * Validate the password change request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasswordChangeRequest(Request $request): void
    {
        $request->validate([
            'current_password' => ['required', 'current_password'],
            'new_password' => ['required', 'confirmed', Password::defaults()],
        ]);
    }

    /**
     * Change the user's password and persist it to the database.
     */
    protected function updateUserPassword(Authenticatable $user, string $newPassword): void
    {
        $user->forceFill([
            'password' => Hash::make($newPassword),
        ])->save();
    }

    /**
     * Emits an event indicating that the user's password has changed.
     */
    protected function emitPasswordChangedEvent(Authenticatable $user): void
    {
        Event::dispatch(new PasswordChanged($user));
    }
}
