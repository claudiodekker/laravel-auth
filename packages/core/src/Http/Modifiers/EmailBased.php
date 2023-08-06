<?php

namespace ClaudioDekker\LaravelAuth\Http\Modifiers;

trait EmailBased
{
    /**
     * The field name used to identify the user.
     */
    protected function usernameField(): string
    {
        return 'email';
    }

    /**
     * Any flavor-specific validation rules used to validate requests that require the username.
     */
    protected function usernameValidationRules(): array
    {
        return ['max:255', 'email'];
    }

    /**
     * Any flavor-specific validation rules used to validate a registration request.
     */
    protected function registrationValidationRules(): array
    {
        return [
            $this->usernameField() => ['required', 'unique:users', ...$this->usernameValidationRules()],
        ];
    }
}
