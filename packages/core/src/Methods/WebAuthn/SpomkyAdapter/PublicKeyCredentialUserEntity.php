<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity as PublicKeyCredentialUserEntityContract;

class PublicKeyCredentialUserEntity extends PublicKeyCredentialUserEntityContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialUserEntity $user): static
    {
        return new static($user->getId(), $user->getName(), $user->getDisplayName());
    }
}
