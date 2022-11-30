<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorTransport;
use JsonSerializable;

/**
 * Represents a type-safe @var AuthenticatorTransports[].
 *
 * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports
 */
class AuthenticatorTransports implements JsonSerializable
{
    /** @var AuthenticatorTransport[] */
    protected array $transports = [];

    /**
     * Create a new array instance.
     *
     * @param  AuthenticatorTransport  ...$transports
     * @return void
     */
    public function __construct(...$transports)
    {
        foreach ($transports as $transport) {
            $this->add($transport);
        }
    }

    /**
     * Add a new item to the array.
     *
     * @param  AuthenticatorTransport  $transport
     * @return $this
     */
    public function add(AuthenticatorTransport $transport): static
    {
        $this->transports[] = $transport;

        return $this;
    }

    /**
     * Get all of the items in the array.
     *
     * @return AuthenticatorTransport[]
     */
    public function all(): array
    {
        return $this->transports;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return mixed
     */
    public function jsonSerialize(): mixed
    {
        return array_map(static fn (AuthenticatorTransport $transport) => $transport->value, $this->all());
    }
}
