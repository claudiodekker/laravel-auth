<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticatorSelectionCriteria as AuthenticatorSelectionCriteriaContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\ResidentKeyRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\UserVerificationRequirement;

class AuthenticatorSelectionCriteria extends AuthenticatorSelectionCriteriaContract
{
    /**
     * Creates a new instance from it's Spomky representation.
     */
    public static function fromSpomky(\Webauthn\AuthenticatorSelectionCriteria $criteria): static
    {
        $authenticatorAttachment = $criteria->getAuthenticatorAttachment();
        $residentKey = $criteria->getResidentKey();

        return new static(
            is_null($authenticatorAttachment) ? null : AuthenticatorAttachment::from($authenticatorAttachment),
            ResidentKeyRequirement::tryFrom($residentKey) ?? ResidentKeyRequirement::PREFERRED,
            UserVerificationRequirement::from($criteria->getUserVerification())
        );
    }
}
