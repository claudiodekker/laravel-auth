<?php

namespace ClaudioDekker\LaravelAuth\Testing\Flavors;

use ClaudioDekker\LaravelAuth\Testing\Helpers;
use Illuminate\Testing\TestResponse;
use Illuminate\Validation\ValidationException;

trait EmailBased
{
    use Helpers;

    protected function usernameField(): string
    {
        return 'email';
    }

    protected function defaultUsername(): string
    {
        return 'claudio@ubient.net';
    }

    protected function anotherUsername(): string
    {
        return 'another@example.com';
    }

    protected function invalidUsername(): string
    {
        return 'foo';
    }

    protected function nonExistentUsername(): string
    {
        return 'foo@example.com';
    }

    protected function tooLongUsername(): string
    {
        return str_repeat('a', 256).'@example.com';
    }

    protected function assertUsernameMustBeValidValidationError(TestResponse $response): void
    {
        $this->assertInstanceOf(ValidationException::class, $response->exception);
        $this->assertSame([$this->usernameField() => [__('validation.email', ['attribute' => $this->usernameField()])]], $response->exception->errors());
    }
}
