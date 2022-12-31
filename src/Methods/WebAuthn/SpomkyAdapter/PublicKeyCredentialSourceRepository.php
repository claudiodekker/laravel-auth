<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorTransport;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Uid\NilUlid;

class PublicKeyCredentialSourceRepository implements \Webauthn\PublicKeyCredentialSourceRepository
{
    public function findOneByCredentialId(string $publicKeyCredentialId): ?\WebAuthn\PublicKeyCredentialSource
    {
        $credential = LaravelAuth::multiFactorCredential()->query()
            ->where('type', CredentialType::PUBLIC_KEY)
            ->find(CredentialType::PUBLIC_KEY->value.'-'.Base64UrlSafe::encodeUnpadded($publicKeyCredentialId));

        if ($credential === null) {
            return null;
        }

        $attributes = CredentialAttributes::fromJson($credential->secret);

        // A lot of the following fields are not required as per the RFC, but are required by the Spomky implementation.
        // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential (step 25)
        // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
        return \Webauthn\PublicKeyCredentialSource::create(
            $attributes->id(),
            \Webauthn\PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            array_map(static fn (AuthenticatorTransport $transport) => $transport->value, $attributes->transports()->all()),
            'invalid',
            new \Webauthn\TrustPath\EmptyTrustPath(),
            new NilUlid(),
            $attributes->publicKey(),
            $attributes->userHandle(),
            $attributes->signCount()
        );
    }

    /**
     * @return \WebAuthn\PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(\Webauthn\PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        throw new LogicException('Not implemented (unused).');
    }

    public function saveCredentialSource(\Webauthn\PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        // Spomky calls this method internally as to provide a way to store update the credential's counter.
        // However, it also returns the same credential data directly after, and since we prefer to give
        // the developer as much control as possible over managing database calls, we'll just ignore
        // this method, and will call an update method ourselves on the controller-level instead.
    }
}
