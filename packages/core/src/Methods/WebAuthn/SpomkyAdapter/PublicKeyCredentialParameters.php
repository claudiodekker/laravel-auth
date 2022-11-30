<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialParameters as PublicKeyCredentialParametersContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\COSEAlgorithmIdentifier;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\PublicKeyCredentialType;

class PublicKeyCredentialParameters extends PublicKeyCredentialParametersContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialParameters $parameters): static
    {
        return new static(
            PublicKeyCredentialType::from($parameters->getType()),
            COSEAlgorithmIdentifier::from($parameters->getAlg()),
        );
    }
}
