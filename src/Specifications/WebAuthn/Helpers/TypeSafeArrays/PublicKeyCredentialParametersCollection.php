<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialParameters;

/**
 * Represents a type-safe @var PublicKeyCredentialParameters[].
 *
 * @link https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
class PublicKeyCredentialParametersCollection implements \JsonSerializable
{
    /** @var PublicKeyCredentialParameters[] */
    protected array $parameters = [];

    /**
     * Create a new array instance.
     *
     * @param  PublicKeyCredentialParameters  ...$parameters
     * @return void
     */
    public function __construct(...$parameters)
    {
        foreach ($parameters as $parameter) {
            $this->add($parameter);
        }
    }

    /**
     * Add a new item to the array.
     *
     * @return $this
     */
    public function add(PublicKeyCredentialParameters $parameter): static
    {
        $this->parameters[] = $parameter;

        return $this;
    }

    /**
     * Get all of the items in the array.
     *
     * @return PublicKeyCredentialParameters[]
     */
    public function all(): array
    {
        return $this->parameters;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): mixed
    {
        return array_map(static fn (PublicKeyCredentialParameters $params) => $params->jsonSerialize(), $this->all());
    }
}
