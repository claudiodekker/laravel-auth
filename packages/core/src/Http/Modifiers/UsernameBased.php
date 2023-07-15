<?php

namespace ClaudioDekker\LaravelAuth\Http\Modifiers;

trait UsernameBased
{
    /**
     * The field name used to identify the user.
     */
    protected function usernameField(): string
    {
        return 'username';
    }

    /**
     * Any flavor-specific validation rules used to validate a registration request.
     */
    protected function registrationValidationRules(): array
    {
        return [
            $this->usernameField() => ['required', 'max:255', 'unique:users'],
            'email' => ['required', 'max:255', 'email'],
        ];
    }

    /**
     * Any flavor-specific validation rules used to validate an authentication request.
     */
    protected function authenticationValidationRules(): array
    {
        return [
            $this->usernameField() => ['required'],
        ];
    }
}
