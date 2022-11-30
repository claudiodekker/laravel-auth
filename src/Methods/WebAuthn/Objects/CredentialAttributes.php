<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects;

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorTransport;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\AuthenticatorTransports;
use Illuminate\Contracts\Support\Jsonable;
use JsonException;
use JsonSerializable;
use LogicException;

class CredentialAttributes implements JsonSerializable, Jsonable
{
    public function __construct(
        protected string $id,
        protected string $publicKey,
        protected int $signCount,
        protected string $userHandle,
        protected AuthenticatorTransports $transports,
    ) {
        //
    }

    /**
     * Decode the given JSON back into an instance.
     *
     * @param  string  $json
     * @return static
     *
     * @throws JsonException
     */
    public static function fromJson(string $json): static
    {
        $data = json_decode($json, false, 512, JSON_THROW_ON_ERROR);

        return new static(
            base64_decode($data->id),
            base64_decode($data->publicKey),
            $data->signCount,
            $data->userHandle,
            new AuthenticatorTransports(...array_map(fn (string $transport) => AuthenticatorTransport::from($transport), $data->transports))
        );
    }

    /**
     * Credential ID.
     *
     * Required to be associated with the user account during the registration ceremony.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential (step 25)
     * @link https://www.w3.org/TR/webauthn-2/#credentialid
     */
    public function id(): string
    {
        return $this->id;
    }

    /**
     * Credential Public Key.
     *
     * Required to be associated with the user account during the registration ceremony.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential (step 25)
     * @link https://www.w3.org/TR/webauthn-2/#credentialpublickey
     */
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Signature Counter.
     *
     * Required to be associated with the user account during the registration ceremony.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential (step 25)
     * @link https://www.w3.org/TR/webauthn-2/#signature-counter
     * @link https://www.w3.org/TR/webauthn-2/#signcount
     */
    public function signCount(): int
    {
        return $this->signCount;
    }

    /**
     * Transport Hints.
     *
     * RECOMMENDED to be associated with the user account during the registration ceremony.
     *
     * It is RECOMMENDED to use this value to populate the transports of the allowCredentials option
     * in future get() calls to help the client know how to find a suitable authenticator.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential (step 25)
     * @link https://www.w3.org/TR/webauthn-2/#credentialpublickey
     */
    public function transports(): AuthenticatorTransports
    {
        return $this->transports;
    }

    /**
     * User Handle.
     *
     * An unique identifier that associates the credential with the user.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion (step 6)
     * @link https://www.w3.org/TR/webauthn-2/#user-handle
     */
    public function userHandle(): ?string
    {
        return $this->userHandle;
    }

    /**
     * Set the Signature Counter.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion (step 21)
     */
    public function setSignCount(int $count): self
    {
        if ($this->signCount() >= $count) {
            // This is a signal that the authenticator may be cloned, i.e. at least two copies of the
            // credential private key may exist and are being used in parallel. Relying Parties
            // should incorporate this information into their risk scoring. Whether the
            // Relying Party updates storedSignCount in this case, or not, or fails
            // the authentication ceremony or not, is Relying Party-specific.
            throw new LogicException('Signature count mismatch for credential ['.$this->id().'].');
        }

        $this->signCount = $count;

        return $this;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return mixed
     */
    public function jsonSerialize(): mixed
    {
        return [
            'id' => base64_encode($this->id),
            'publicKey' => base64_encode($this->publicKey),
            'signCount' => $this->signCount,
            'userHandle' => $this->userHandle,
            'transports' => $this->transports->jsonSerialize(),
        ];
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     * @return string
     *
     * @throws JsonException
     */
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), JSON_THROW_ON_ERROR);
    }
}
