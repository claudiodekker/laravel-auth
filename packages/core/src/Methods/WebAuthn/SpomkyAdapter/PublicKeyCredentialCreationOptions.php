<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\ClientExtension;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticationExtensionsClientInputs;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions as PublicKeyCredentialCreationOptionsContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AttestationConveyancePreference;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialDescriptors;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialParametersCollection;
use Illuminate\Support\Collection;

class PublicKeyCredentialCreationOptions extends PublicKeyCredentialCreationOptionsContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\PublicKeyCredentialCreationOptions $options): static
    {
        return new static(
            PublicKeyCredentialRpEntity::fromSpomky($options->getRp()),
            PublicKeyCredentialUserEntity::fromSpomky($options->getUser()),
            $options->getChallenge(),
            new PublicKeyCredentialParametersCollection(
                ...Collection::make($options->getPubKeyCredParams())
                ->map(fn (\Webauthn\PublicKeyCredentialParameters $parameters) => PublicKeyCredentialParameters::fromSpomky($parameters))
                ->all()
            ),
            $options->getTimeout(),
            AuthenticatorSelectionCriteria::fromSpomky($options->getAuthenticatorSelection()),
            new PublicKeyCredentialDescriptors(
                ...Collection::make($options->getExcludeCredentials())
                ->map(fn (\Webauthn\PublicKeyCredentialDescriptor $descriptor) => PublicKeyCredentialDescriptor::fromSpomky($descriptor))
                ->all()
            ),
            AttestationConveyancePreference::from($options->getAttestation()),
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

    /**
     * Extends parent-behaviour as to polyfill 'missing' fields.
     *
     * @link https://github.com/web-auth/webauthn-framework/issues/234
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        $options = parent::jsonSerialize();

        if (! isset($options['attestation'])) {
            $options['attestation'] = AttestationConveyancePreference::NONE->value;
        }

        if (! isset($options['authenticatorSelection'])) {
            $options['authenticatorSelection'] = (new AuthenticatorSelectionCriteria())->jsonSerialize();
        }

        return $options;
    }
}
