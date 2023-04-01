<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialDescriptor;
use JsonSerializable;

/**
 * Represents a type-safe @var PublicKeyCredentialDescriptors[].
 *
 * @link https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
class PublicKeyCredentialDescriptors implements JsonSerializable
{
    /** @var PublicKeyCredentialDescriptor[] */
    protected array $descriptors = [];

    /**
     * Create a new array instance.
     *
     * @param  PublicKeyCredentialDescriptor  ...$descriptors
     * @return void
     */
    public function __construct(...$descriptors)
    {
        foreach ($descriptors as $descriptor) {
            $this->set($descriptor);
        }
    }

    /**
     * Set a new item in the array.
     */
    public function set(PublicKeyCredentialDescriptor $descriptor): static
    {
        $this->descriptors[$descriptor->id()] = $descriptor;

        return $this;
    }

    /**
     * Get all of the items in the array.
     *
     * @return PublicKeyCredentialDescriptor[]
     */
    public function all(): array
    {
        return array_values($this->descriptors);
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): mixed
    {
        return array_map(static fn (PublicKeyCredentialDescriptor $descriptor) => $descriptor->jsonSerialize(), $this->all());
    }
}
