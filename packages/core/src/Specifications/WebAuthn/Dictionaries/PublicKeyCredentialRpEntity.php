<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use JsonSerializable;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialentity
 */
class PublicKeyCredentialRpEntity implements JsonSerializable
{
    public function __construct(
        protected ?string $id,
        protected string $name,
    ) {
        //
    }

    /**
     * A unique identifier for the Relying Party entity, which sets the RP ID.
     *
     * In the context of the WebAuthn API, a relying party identifier is a valid domain
     * string identifying the WebAuthn Relying Party on whose behalf a given
     * registration or authentication ceremony is being performed.
     *
     * When omitted, its value will be the CredentialsContainer object’s relevant settings object's
     * origin's effective domain. See § 5.4.2 Relying Party Parameters for Credential Generation
     * (dictionary PublicKeyCredentialRpEntity) for further details.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id
     * @link https://www.w3.org/TR/webauthn-2/#rp-id
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp
     */
    public function id(): ?string
    {
        return $this->id;
    }

    /**
     * A human-palatable identifier for the Relying Party.
     *
     * It is intended only for display. For example, "ACME Corporation",
     * "Wonderful Widgets, Inc." or "ОАО Примертех".
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialentity
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize(): array
    {
        $data = ['name' => $this->name()];

        if (! is_null($id = $this->id())) {
            $data['id'] = $id;
        }

        return $data;
    }
}
