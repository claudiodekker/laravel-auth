<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\ClientExtension;

/**
 * @see \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticationExtensionsClientInputs
 * @see \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticationExtensionsClientOutputs
 */
abstract class ClientExtensions
{
    /** @var ClientExtension[] */
    protected array $inputs = [];

    /**
     * Create a new client extension collection instance.
     *
     * @param  ClientExtension  ...$values
     * @return void
     */
    public function __construct(...$values)
    {
        foreach ($values as $value) {
            $this->set($value);
        }
    }

    /**
     * Set a new item in the collection.
     *
     * @param  ClientExtension  $value
     * @return $this
     */
    public function set(ClientExtension $value): static
    {
        $this->inputs[$value->key()] = $value;

        return $this;
    }

    /**
     * Get all of the items in the collection.
     *
     * @return ClientExtension[]
     */
    public function all(): array
    {
        return $this->inputs;
    }
}
