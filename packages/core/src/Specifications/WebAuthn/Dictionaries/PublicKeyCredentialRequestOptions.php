<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\UserVerificationRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\PublicKeyCredentialDescriptors;
use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
 */
abstract class PublicKeyCredentialRequestOptions implements JsonSerializable
{
    public function __construct(
        protected string $challenge,
        protected ?int $timeout,
        protected ?string $rpId,
        protected PublicKeyCredentialDescriptors $allowCredentials = new PublicKeyCredentialDescriptors(),
        protected UserVerificationRequirement $userVerification = UserVerificationRequirement::PREFERRED,
        protected AuthenticationExtensionsClientInputs $extensions = new AuthenticationExtensionsClientInputs()
    ) {
        //
    }

    /**
     * A challenge that gets signed by the authenticator (along with other data) during the authentication ceremony.
     *
     * @link https://www.w3.org/TR/webauthn-2/#authentication-assertion
     */
    public function challenge(): string
    {
        return Base64UrlSafe::encodeUnpadded($this->challenge);
    }

    /**
     * A time, in milliseconds, that the caller is willing to wait for the call to complete.
     * This is treated as a hint, and MAY be overridden by the client.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout
     */
    public function timeout(): ?int
    {
        return $this->timeout;
    }

    /**
     * A unique identifier for the Relying Party entity.
     *
     * In the context of the WebAuthn API, a relying party identifier is a valid domain
     * string identifying the WebAuthn Relying Party on whose behalf a given
     * registration or authentication ceremony is being performed.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id
     * @link https://www.w3.org/TR/webauthn-2/#rp-id
     *
     * When omitted, its value will be the CredentialsContainer object’s relevant
     * settings object's origin's effective domain.
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid
     */
    public function rpId(): ?string
    {
        return $this->rpId;
    }

    /**
     * Represents the public key credentials acceptable to the caller, in descending order of the caller’s preference
     * (the first item in the list is the most preferred credential, and so on down the list).
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials
     */
    public function allowCredentials(): PublicKeyCredentialDescriptors
    {
        return $this->allowCredentials;
    }

    /**
     * The Relying Party's requirements regarding user verification for the get() operation.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification
     */
    public function userVerification(): UserVerificationRequirement
    {
        return $this->userVerification;
    }

    /**
     * Additional parameters requesting additional processing by the client and authenticator.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions
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
            'challenge' => $this->challenge(),
        ];

        if (! is_null($rpId = $this->rpId())) {
            $data['rpId'] = $rpId;
        }

        if (! is_null($timeout = $this->timeout())) {
            $data['timeout'] = $timeout;
        }

        if (count($allowCredentials = $this->allowCredentials()->jsonSerialize()) > 0) {
            $data['allowCredentials'] = $allowCredentials;
        }

        $userVerification = $this->userVerification();
        if ($userVerification !== UserVerificationRequirement::PREFERRED) {
            $data['userVerification'] = $userVerification->value;
        }

        if (count($extensions = $this->extensions()->all()) > 0) {
            $data['extensions'] = $extensions;
        }

        return $data;
    }
}
