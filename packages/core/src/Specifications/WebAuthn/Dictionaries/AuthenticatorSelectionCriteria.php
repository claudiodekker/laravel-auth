<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\ResidentKeyRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\UserVerificationRequirement;
use JsonSerializable;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
 */
abstract class AuthenticatorSelectionCriteria implements JsonSerializable
{
    protected bool $requireResidentKey = false;

    public function __construct(
        protected ?AuthenticatorAttachment $authenticatorAttachment = null,
        protected ?ResidentKeyRequirement $residentKey = null,
        protected UserVerificationRequirement $userVerification = UserVerificationRequirement::PREFERRED,
    ) {
        /**
         * This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons, its
         * naming retains the deprecated "resident" terminology for discoverable credentials. Relying Parties
         * SHOULD set it to true if, and only if, residentKey is set to required.
         *
         * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
         */
        $this->requireResidentKey = $this->residentKey === ResidentKeyRequirement::REQUIRED;
    }

    /**
     * Filter to only include eligible authenticators attached with the specified enum.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment
     */
    public function authenticatorAttachment(): ?AuthenticatorAttachment
    {
        return $this->authenticatorAttachment;
    }

    /**
     * Specifies the extent to which the Relying Party desires to create a client-side discoverable credential.
     * For historical reasons the naming retains the deprecated "resident" terminology.
     *
     * If no value is given then the effective value is required if requireResidentKey
     * is true or discouraged if it is false or absent.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
     */
    public function residentKey(): ?ResidentKeyRequirement
    {
        return $this->residentKey;
    }

    /**
     * Retained for backwards compatibility with WebAuthn Level 1.
     * For historical reasons the naming retains the deprecated "resident" terminology for discoverable credentials.
     *
     * Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
     */
    public function requireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    /**
     * The Relying Party's requirements regarding user verification for the create() operation.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification
     */
    public function userVerification(): UserVerificationRequirement
    {
        return $this->userVerification;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        $data = [];

        if (! is_null($authenticatorAttachment = $this->authenticatorAttachment())) {
            $data['authenticatorAttachment'] = $authenticatorAttachment->value;
        }

        if (! is_null($residentKey = $this->residentKey())) {
            $data['residentKey'] = $residentKey->value;
        }

        if ($this->requireResidentKey()) {
            $data['requireResidentKey'] = true;
        }

        $userVerification = $this->userVerification();
        if ($userVerification !== UserVerificationRequirement::PREFERRED) {
            $data['userVerification'] = $userVerification->value;
        }

        return $data;
    }
}
