<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\COSEAlgorithmIdentifier;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\PublicKeyCredentialType;
use JsonSerializable;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters
 */
class PublicKeyCredentialParameters implements JsonSerializable
{
    public function __construct(
        protected PublicKeyCredentialType $type,
        protected COSEAlgorithmIdentifier $alg,
    ) {
        //
    }

    /**
     * The type of credential to be created.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type
     */
    public function type(): PublicKeyCredentialType
    {
        return $this->type;
    }

    /**
     * The the cryptographic signature algorithm with which the newly generated credential will be used,
     * and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg
     */
    public function alg(): COSEAlgorithmIdentifier
    {
        return $this->alg;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type()->value,
            'alg' => $this->alg()->value,
        ];
    }
}
