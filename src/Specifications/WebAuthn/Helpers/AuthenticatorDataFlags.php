<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\Enums\AuthenticatorDataBit;

/**
 * @link https://www.w3.org/TR/webauthn-2/#flags
 */
class AuthenticatorDataFlags
{
    public function __construct(
        protected string $flags /** @see AuthenticatorDataBit */
    ) {
        //
    }

    /**
     * The raw flag bits.
     *
     * bit 0 is the least significant bit.
     */
    public function raw(): string
    {
        return $this->flags;
    }

    /**
     * Bit 0: User Present (UP) result.
     *
     * - 1 means the user is present.
     * - 0 means the user is not present.
     *
     * @link https://www.w3.org/TR/webauthn-2/#concept-user-present
     * @link https://www.w3.org/TR/webauthn-2/#up
     */
    public function isUserPresent(): bool
    {
        return 0 !== (ord($this->flags) & AuthenticatorDataBit::USER_PRESENT->value);
    }

    /**
     * Bit 1: Reserved for future use (RFU1).
     */
    public function isReservedForFutureUse1(): int
    {
        return ord($this->flags) & AuthenticatorDataBit::RESERVED_FUTURE_USE_RFU1->value;
    }

    /**
     * Bit 2: User Verified (UV) result.
     *
     * - 1 means the user is verified.
     * - 0 means the user is not verified.
     *
     * @link https://www.w3.org/TR/webauthn-2/#concept-user-verified
     * @link https://www.w3.org/TR/webauthn-2/#uv
     */
    public function isUserVerified(): bool
    {
        return 0 !== (ord($this->flags) & AuthenticatorDataBit::USER_VERIFIED->value);
    }

    /**
     * Bits 3-5: Reserved for future use (RFU2).
     */
    public function isReservedForFutureUse2(): int
    {
        return ord($this->flags) & AuthenticatorDataBit::RESERVED_FUTURE_USE_RFU2->value;
    }

    /**
     * Bit 6: Attested credential data included (AT).
     *
     * Indicates whether the authenticator added attested credential data.
     *
     * @link https://www.w3.org/TR/webauthn-2/#attested-credential-data
     */
    public function hasAttestedCredentialData(): bool
    {
        return 0 !== (ord($this->flags) & AuthenticatorDataBit::ATTESTED_CREDENTIAL_DATA->value);
    }

    /**
     * Bit 7: Extension data included (ED).
     *
     * Indicates if the authenticator data has extensions.
     *
     * @link https://www.w3.org/TR/webauthn-2/#authenticator-data
     * @link https://www.w3.org/TR/webauthn-2/#authdataextensions
     */
    public function hasExtensions(): bool
    {
        return 0 !== (ord($this->flags) & AuthenticatorDataBit::EXTENSION_DATA_INCLUDED->value);
    }
}
