<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts;

use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use Illuminate\Support\Collection;
use Psr\Http\Message\ServerRequestInterface;

interface WebAuthnContract
{
    /**
     * Prepares the challenge options used to create a new (multi-factor) public key credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#server-side-public-key-credential-source
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
     */
    public function generatePublicKeyCreationOptions(PublicKeyCredentialUserEntity $user, Collection $excludeCredentials = null): PublicKeyCredentialCreationOptions;

    /**
     * Prepares the challenge options used to create a new passkey credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
     */
    public function generatePasskeyCreationOptions(PublicKeyCredentialUserEntity $user): PublicKeyCredentialCreationOptions;

    /**
     * Loads, parses and validates the incoming authenticator attestation response.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    public function getAttestedCredentialAttributes(ServerRequestInterface $request, PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions): CredentialAttributes;

    /**
     * Prepares the challenge options used to authenticate a (multi-factor) public key credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
     */
    public function generatePublicKeyRequestOptions(Collection $allowCredentials = null): PublicKeyCredentialRequestOptions;

    /**
     * Prepares the challenge options used to authenticate a passkey credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
     */
    public function generatePasskeyRequestOptions(): PublicKeyCredentialRequestOptions;

    /**
     * Validates the signed public key credential challenge for the given options.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    public function validateCredential(ServerRequestInterface $request, PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions, PublicKeyCredentialUserEntity $user = null): CredentialAttributes;
}
