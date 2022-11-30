<?php

namespace ClaudioDekker\LaravelAuth\Http\Traits;

trait UsernameBased
{
    /**
     * The field name used to identify the user.
     *
     * @return string
     */
    protected function usernameField(): string
    {
        return 'username';
    }

    /**
     * Any flavor-specific validation rules used to validate a registration request.
     *
     * @return array
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
     *
     * @return array
     */
    protected function authenticationValidationRules(): array
    {
        return [
            $this->usernameField() => ['required'],
        ];
    }
}
