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
     * Any flavor-specific validation rules used to validate requests that require the username.
     */
    protected function usernameValidationRules(): array
    {
        return ['max:255', 'string'];
    }

    /**
     * Any flavor-specific validation rules used to validate a registration request.
     */
    protected function registrationValidationRules(): array
    {
        return [
            $this->usernameField() => ['required', 'unique:users', ...$this->usernameValidationRules()],
            'email' => ['required', 'max:255', 'email'],
        ];
    }
}
