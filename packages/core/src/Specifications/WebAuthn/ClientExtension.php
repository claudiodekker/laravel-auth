<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn;

/**
 * @link https://www.w3.org/TR/webauthn-2/#client-extension-input
 * @link https://www.w3.org/TR/webauthn-2/#client-extension-output
 */
class ClientExtension
{
    public function __construct(
        protected string $key,
        protected mixed $value,
    ) {
        //
    }

    public function key(): string
    {
        return $this->key;
    }

    public function value(): mixed
    {
        return $this->value;
    }
}
