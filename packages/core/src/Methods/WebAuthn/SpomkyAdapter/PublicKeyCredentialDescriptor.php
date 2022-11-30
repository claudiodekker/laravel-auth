<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialDescriptor as PublicKeyCredentialDescriptorContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorTransport;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\PublicKeyCredentialType;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\AuthenticatorTransports;
use Illuminate\Support\Collection;

class PublicKeyCredentialDescriptor extends PublicKeyCredentialDescriptorContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialDescriptor $descriptor): static
    {
        return new static(
            PublicKeyCredentialType::from($descriptor->getType()),
            $descriptor->getId(),
            new AuthenticatorTransports(
                ...Collection::make($descriptor->getTransports())
                ->map(fn (string $transport) => AuthenticatorTransport::from($transport))
                ->all()
            )
        );
    }
}
