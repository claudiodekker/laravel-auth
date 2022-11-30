<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRpEntity as PublicKeyCredentialRpEntityContract;

class PublicKeyCredentialRpEntity extends PublicKeyCredentialRpEntityContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialRpEntity $rp): static
    {
        return new static($rp->getId(), $rp->getName());
    }
}
