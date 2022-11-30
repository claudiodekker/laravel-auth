<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn;

/**
 * @link https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
 * @link https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
 */
class AttestedCredentialData
{
    public function __construct(
        protected string $aaguid,
        protected string $credentialId,
        protected ?string $credentialPublicKey
    ) {
        //
    }

    /**
     * The AAGUID of the authenticator.
     *
     * @link https://www.w3.org/TR/webauthn-2/#aaguid
     */
    public function aaguid(): string
    {
        return $this->aaguid;
    }

    /**
     * Byte length L of Credential ID, 16-bit unsigned big-endian integer.
     *
     * @link https://www.w3.org/TR/webauthn-2/#credentialid
     */
    public function credentialIdLength(): int
    {
        return strlen($this->credentialId);
    }

    /**
     * The credential ID.
     *
     * @link https://www.w3.org/TR/webauthn-2/#credentialid
     */
    public function credentialId(): string
    {
        return $this->credentialId;
    }

    /**
     * The credential public key.
     *
     * The credential public key encoded in COSE_Key format, as defined in Section 7
     * of [RFC8152], using the CTAP2 canonical CBOR encoding form.
     *
     * The COSE_Key-encoded credential public key MUST contain the "alg" parameter
     * and MUST NOT contain any other OPTIONAL parameters. The "alg" parameter
     * MUST contain a COSEAlgorithmIdentifier value.
     *
     * The encoded credential public key MUST also contain any additional REQUIRED parameters
     * stipulated by the relevant key type specification, i.e., REQUIRED for the
     * key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]).
     *
     * @link https://www.w3.org/TR/webauthn-2/#credentialpublickey
     * @link https://www.w3.org/TR/webauthn-2/#credential-public-key
     * @link https://tools.ietf.org/html/rfc8152#section-7
     * @link https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
     * @link https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
     * @link https://www.w3.org/TR/webauthn-2/#biblio-rfc8152
     */
    public function credentialPublicKey(): ?string
    {
        return $this->credentialPublicKey;
    }
}
