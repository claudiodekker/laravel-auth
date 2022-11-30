<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticationExtensionsClientOutputs;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\AuthenticatorDataFlags;

/**
 * @link https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
 */
class AuthenticatorData
{
    public function __construct(
        protected string $rpIdHash,
        protected AuthenticatorDataFlags $flags,
        protected int $signCount,
        protected ?AttestedCredentialData $attestedCredentialData,
        protected ?AuthenticationExtensionsClientOutputs $extensions,
    ) {
        //
    }

    /**
     * SHA-256 hash of the RP ID the credential is scoped to.
     *
     * @link https://www.w3.org/TR/webauthn-2/#rpidhash
     * @link https://www.w3.org/TR/webauthn-2/#rp-id
     */
    public function rpIdHash(): string
    {
        return $this->rpIdHash;
    }

    /**
     * @link https://www.w3.org/TR/webauthn-2/#flags
     * @see AuthenticatorDataFlags
     */
    public function flags(): AuthenticatorDataFlags
    {
        return $this->flags;
    }

    /**
     * Signature counter, 32-bit unsigned big-endian integer.
     *
     * @link https://www.w3.org/TR/webauthn-2/#signcount
     * @link https://www.w3.org/TR/webauthn-2/#signature-counter
     */
    public function signCount(): int
    {
        return $this->signCount;
    }

    /**
     * Attested credential data (if present).
     *
     * See § 6.5.1 Attested Credential Data for details.
     * Its length depends on the length of the credential ID and credential public key being attested.
     *
     * @link https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
     * @link https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
     */
    public function attestedCredentialData(): ?AttestedCredentialData
    {
        return $this->attestedCredentialData;
    }

    /**
     *  Extension-defined authenticator data.
     *
     * This is a CBOR [RFC8949] map with extension identifiers as keys, and authenticator
     * extension outputs as values. See § 9 WebAuthn Extensions for details.
     *
     * @link https://www.w3.org/TR/webauthn-2/#authdataextensions
     * @link https://www.w3.org/TR/webauthn-2/#sctn-extensions
     */
    public function extensions(): ?AuthenticationExtensionsClientOutputs
    {
        return $this->extensions;
    }
}
