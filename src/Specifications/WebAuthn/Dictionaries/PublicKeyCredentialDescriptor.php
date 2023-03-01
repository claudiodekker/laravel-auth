<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\PublicKeyCredentialType;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\AuthenticatorTransports;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
 */
class PublicKeyCredentialDescriptor implements JsonSerializable
{
    public function __construct(
        protected PublicKeyCredentialType $type,
        protected string $id,
        protected AuthenticatorTransports $transports = new AuthenticatorTransports(),
    ) {
        //
    }

    /**
     * The type of the public key credential the caller is referring to.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type
     */
    public function type(): PublicKeyCredentialType
    {
        return $this->type;
    }

    /**
     * The credential ID of the public key credential the caller is referring to.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id
     */
    public function id(): string
    {
        return $this->id;
    }

    /**
     * A hint as to how the client might communicate with the managing authenticator
     * of the public key credential the caller is referring to.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports
     */
    public function transports(): AuthenticatorTransports
    {
        return $this->transports;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        $data = [
            'type' => $this->type()->value,
            'id' => Base64UrlSafe::encodeUnpadded($this->id()),
        ];

        if (count($transports = $this->transports()->jsonSerialize()) > 0) {
            $data['transports'] = $transports;
        }

        return $data;
    }
}
