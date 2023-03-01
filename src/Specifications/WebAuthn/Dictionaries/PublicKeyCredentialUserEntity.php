<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries;

use JsonSerializable;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity
 * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialentity
 */
class PublicKeyCredentialUserEntity implements JsonSerializable
{
    public function __construct(
        protected string $id,
        protected string $name,
        protected string $displayName,
    ) {
        //
    }

    /**
     * A human-palatable identifier for a user account.
     *
     * It is intended only for display. For example, "alexm",
     * "alex.mueller@example.com" or "+14255551234".
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialentity
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * The user handle of the user account entity.
     *
     * To ensure secure operation, authentication and authorization decisions MUST be
     * made on the basis of this id member. Not meant to be displayed to the user.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id
     */
    public function id(): string
    {
        return $this->id;
    }

    /**
     * A human-palatable name for the user account.
     *
     * It is intended only for display. For example, "Alex Müller" or "田中倫".
     * The Relying Party SHOULD let the user choose this, and SHOULD NOT
     * restrict the choice more than necessary.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname
     */
    public function displayName(): string
    {
        return $this->displayName;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return [
            'name' => $this->name(),
            'id' => Base64UrlSafe::encodeUnpadded($this->id()),
            'displayName' => $this->displayName(),
        ];
    }
}
