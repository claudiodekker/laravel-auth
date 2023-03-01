<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\AuthenticatorSelectionCriteria as AuthenticatorSelectionCriteriaContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRpEntity as PublicKeyCredentialRpEntityContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity as PublicKeyCredentialUserEntityContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AttestationConveyancePreference;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialDescriptors;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialParametersCollection;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
abstract class PublicKeyCredentialCreationOptions implements JsonSerializable
{
    public function __construct(
        protected PublicKeyCredentialRpEntityContract $rp,
        protected PublicKeyCredentialUserEntityContract $user,
        protected string $challenge,
        protected PublicKeyCredentialParametersCollection $pubKeyCredParams,
        protected ?int $timeout,
        protected AuthenticatorSelectionCriteriaContract $authenticatorSelection,
        protected PublicKeyCredentialDescriptors $excludeCredentials = new PublicKeyCredentialDescriptors(),
        protected AttestationConveyancePreference $attestation = AttestationConveyancePreference::NONE,
        protected AuthenticationExtensionsClientInputs $extensions = new AuthenticationExtensionsClientInputs()
    ) {
        //
    }

    /**
     * The Relying Party responsible for the request.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp
     */
    public function rp(): PublicKeyCredentialRpEntityContract
    {
        return $this->rp;
    }

    /**
     * The user account for which the Relying Party is requesting attestation.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
     */
    public function user(): PublicKeyCredentialUserEntityContract
    {
        return $this->user;
    }

    /**
     * A challenge intended to be used for generating the newly created credential's attestation object.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge
     */
    public function challenge(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->challenge);
    }

    /**
     * The desired properties of the credential to be created.
     *
     * The sequence is ordered from most preferred to least preferred.
     * The client makes a best-effort to create the most preferred credential that it can.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams
     */
    public function pubKeyCredParams(): PublicKeyCredentialParametersCollection
    {
        return $this->pubKeyCredParams;
    }

    /**
     * A time, in milliseconds, that the caller is willing to wait for the call to complete.
     * This is treated as a hint, and MAY be overridden by the client.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout
     */
    public function timeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * Intended to limit the creation of multiple credentials for the same account on a single authenticator.
     *
     * The client is requested to return an error if the new credential would be created on an
     * authenticator that also contains one of the credentials enumerated in this parameter.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials
     */
    public function excludeCredentials(): PublicKeyCredentialDescriptors
    {
        return $this->excludeCredentials;
    }

    /**
     * Intended for use by Relying Parties that wish to select the appropriate
     * authenticators to participate in the create() operation.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection
     */
    public function authenticatorSelection(): AuthenticatorSelectionCriteriaContract
    {
        return $this->authenticatorSelection;
    }

    /**
     * Intended for use by Relying Parties that wish to express their preference for attestation conveyance.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation
     */
    public function attestation(): AttestationConveyancePreference
    {
        return $this->attestation;
    }

    /**
     * Additional parameters requesting additional processing by the client and authenticator.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions
     */
    public function extensions(): AuthenticationExtensionsClientInputs
    {
        return $this->extensions;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        $data = [
            'rp' => $this->rp()->jsonSerialize(),
            'user' => $this->user()->jsonSerialize(),
            'challenge' => $this->challenge(),
            'pubKeyCredParams' => $this->pubKeyCredParams()->jsonSerialize(),
        ];

        if (! is_null($timeout = $this->timeout())) {
            $data['timeout'] = $timeout;
        }

        if (count($excludeCredentials = $this->excludeCredentials()->jsonSerialize()) > 0) {
            $data['excludeCredentials'] = $excludeCredentials;
        }

        if (count($authenticatorSelection = $this->authenticatorSelection()->jsonSerialize()) > 0) {
            $data['authenticatorSelection'] = $authenticatorSelection;
        }

        if ($this->attestation !== AttestationConveyancePreference::NONE) {
            $data['attestation'] = $this->attestation()->value;
        }

        if (count($extensions = $this->extensions()->all()) > 0) {
            $data['extensions'] = $extensions;
        }

        return $data;
    }
}
