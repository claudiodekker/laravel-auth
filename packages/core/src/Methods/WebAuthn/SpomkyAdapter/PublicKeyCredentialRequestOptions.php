<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\ClientExtension;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticationExtensionsClientInputs;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions as PublicKeyCredentialRequestOptionsContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\UserVerificationRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialDescriptors;
use Illuminate\Support\Collection;

class PublicKeyCredentialRequestOptions extends PublicKeyCredentialRequestOptionsContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialRequestOptions $options): static
    {
        return new static(
            $options->getChallenge(),
            $options->getTimeout(),
            $options->getRpId(),
            new PublicKeyCredentialDescriptors(
                ...Collection::make($options->getAllowCredentials())
                    ->map(fn (\Webauthn\PublicKeyCredentialDescriptor $descriptor) => PublicKeyCredentialDescriptor::fromSpomky($descriptor))
                    ->all()
            ),
            UserVerificationRequirement::tryFrom($options->getUserVerification() ?? UserVerificationRequirement::PREFERRED->value),
            new AuthenticationExtensionsClientInputs(
                ...Collection::make($options->getExtensions())
                    ->map(fn (\Webauthn\AuthenticationExtensions\AuthenticationExtension $extension) => new ClientExtension(
                        $extension->name(),
                        $extension->value()
                    ))
                    ->all()
            )
        );
    }
}
