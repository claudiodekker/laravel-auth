<?php

namespace ClaudioDekker\LaravelAuth\Methods\WebAuthn;

use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter\PublicKeyCredentialRequestOptions;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\SpomkyAdapter\PublicKeyCredentialSourceRepository;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions as PublicKeyCredentialCreationOptionsContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions as PublicKeyCredentialRequestOptionsContract;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AttestationConveyancePreference;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorTransport;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\COSEAlgorithmIdentifier;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\ResidentKeyRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\UserVerificationRequirement;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\TypeSafeArrays\AuthenticatorTransports;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\ECDSA\ES256K;
use Cose\Algorithm\Signature\ECDSA\ES384;
use Cose\Algorithm\Signature\ECDSA\ES512;
use Cose\Algorithm\Signature\EdDSA\Ed256;
use Cose\Algorithm\Signature\EdDSA\Ed512;
use Cose\Algorithm\Signature\RSA\PS256;
use Cose\Algorithm\Signature\RSA\PS384;
use Cose\Algorithm\Signature\RSA\PS512;
use Cose\Algorithm\Signature\RSA\RS256;
use Cose\Algorithm\Signature\RSA\RS384;
use Cose\Algorithm\Signature\RSA\RS512;
use Exception;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AppleAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;

class SpomkyWebAuthn implements WebAuthnContract
{
    /**
     * Prepares the challenge options used to create a new (multi-factor) public key credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#server-side-public-key-credential-source
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
     *
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity  $user
     * @param  \Illuminate\Support\Collection|null  $excludeCredentials
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions
     */
    public function generatePublicKeyCreationOptions(PublicKeyCredentialUserEntity $user, ?Collection $excludeCredentials = null): PublicKeyCredentialCreationOptionsContract
    {
        $options = \Webauthn\PublicKeyCredentialCreationOptions::create(
            $this->relyingPartyEntity(),
            $this->userEntity($user),
            $this->generateChallenge(),
            $this->publicKeyCredentialParameters()
        )
            ->setTimeout($this->timeout())
            ->excludeCredentials(...$this->prepareCredentials($excludeCredentials))
            ->setAuthenticatorSelection($this->multiFactorCredentialAuthenticatorSelectionCriteria())
            ->setAttestation($this->attestation());

        return PublicKeyCredentialCreationOptions::fromSpomky($options);
    }

    /**
     * Prepares the challenge options used to create a new passkey credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
     *
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity  $user
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions
     */
    public function generatePasskeyCreationOptions(PublicKeyCredentialUserEntity $user): PublicKeyCredentialCreationOptionsContract
    {
        $options = \Webauthn\PublicKeyCredentialCreationOptions::create(
            $this->relyingPartyEntity(),
            $this->userEntity($user),
            $this->generateChallenge(),
            $this->publicKeyCredentialParameters()
        )
            ->setTimeout($this->timeout())
            ->setAuthenticatorSelection($this->passkeyBasedAuthenticatorSelectionCriteria())
            ->setAttestation($this->attestation());

        return PublicKeyCredentialCreationOptions::fromSpomky($options);
    }

    /**
     * Loads, parses and validates the incoming authenticator attestation response.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $publicKeyCredentialCreationOptions
     * @return \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    public function getAttestedCredentialAttributes(ServerRequestInterface $request, PublicKeyCredentialCreationOptionsContract $publicKeyCredentialCreationOptions): CredentialAttributes
    {
        $parsedBody = $request->getParsedBody();
        if (! is_array($parsedBody) || ! array_key_exists('credential', $parsedBody) || ! is_array($parsedBody['credential'])) {
            throw new InvalidPublicKeyCredentialException('The credential parameter is missing or invalid.');
        }

        $authenticatorResponse = $this->loadPublicKeyCredential($parsedBody['credential'])->getResponse();
        if (! $authenticatorResponse instanceof AuthenticatorAttestationResponse) {
            throw new UnexpectedActionException('The received response is not an attestation response');
        }

        $validator = $this->getAuthenticatorAttestationResponseValidator();
        $creationOptions = \Webauthn\PublicKeyCredentialCreationOptions::createFromArray(
            $publicKeyCredentialCreationOptions->jsonSerialize()
        );

        try {
            $publicKeyCredentialSource = $validator->check($authenticatorResponse, $creationOptions, $request);
        } catch (Throwable $exception) {
            throw new InvalidPublicKeyCredentialException($exception->getMessage(), $exception->getCode(), $exception);
        }

        return new CredentialAttributes(
            $publicKeyCredentialSource->getAttestedCredentialData()->getCredentialId(),
            $publicKeyCredentialSource->getAttestedCredentialData()->getCredentialPublicKey(),
            $publicKeyCredentialSource->getCounter(),
            $publicKeyCredentialSource->getUserHandle(),
            new AuthenticatorTransports(...array_map(
                static fn (string $transport) => AuthenticatorTransport::from($transport),
                $publicKeyCredentialSource->getTransports()
            ))
        );
    }

    /**
     * Prepares the challenge options used to authenticate a (multi-factor) public key credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
     *
     * @param  \Illuminate\Support\Collection|null  $allowCredentials
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions
     */
    public function generatePublicKeyRequestOptions(?Collection $allowCredentials = null): PublicKeyCredentialRequestOptionsContract
    {
        $options = \Webauthn\PublicKeyCredentialRequestOptions::create(
            $this->generateChallenge(),
        )
            ->setRpId($this->relyingPartyEntity()->getId())
            ->setTimeout($this->timeout())
            ->setUserVerification(UserVerificationRequirement::DISCOURAGED->value)
            ->allowCredentials(...$this->prepareCredentials($allowCredentials));

        return PublicKeyCredentialRequestOptions::fromSpomky($options);
    }

    /**
     * Prepares the challenge options used to authenticate a passkey credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions
     *
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions
     */
    public function generatePasskeyRequestOptions(): PublicKeyCredentialRequestOptionsContract
    {
        $options = \Webauthn\PublicKeyCredentialRequestOptions::create(
            $this->generateChallenge(),
        )
            ->setRpId($this->relyingPartyEntity()->getId())
            ->setUserVerification(UserVerificationRequirement::REQUIRED->value);

        return PublicKeyCredentialRequestOptions::fromSpomky($options);
    }

    /**
     * Validates the signed public key credential challenge for the given options.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions  $publicKeyCredentialRequestOptions
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity|null  $user
     * @return \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    public function validateCredential(ServerRequestInterface $request, PublicKeyCredentialRequestOptionsContract $publicKeyCredentialRequestOptions, ?PublicKeyCredentialUserEntity $user = null): CredentialAttributes
    {
        $parsedBody = $request->getParsedBody();
        if (! is_array($parsedBody) || ! array_key_exists('credential', $parsedBody) || ! is_array($parsedBody['credential'])) {
            throw new InvalidPublicKeyCredentialException('The credential parameter is missing or invalid.');
        }

        $publicKeyCredential = $this->loadPublicKeyCredential($parsedBody['credential']);

        $authenticatorResponse = $publicKeyCredential->getResponse();
        if (! $authenticatorResponse instanceof AuthenticatorAssertionResponse) {
            throw new UnexpectedActionException('The received response is not an assertion response');
        }

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $requestOptions = \Webauthn\PublicKeyCredentialRequestOptions::createFromArray(
            $publicKeyCredentialRequestOptions->jsonSerialize()
        );

        try {
            $publicKeyCredentialSource = $validator->check(
                $publicKeyCredential->getRawId(),
                $authenticatorResponse,
                $requestOptions,
                $request,
                $user?->id(),
            );
        } catch (Throwable $exception) {
            throw new InvalidPublicKeyCredentialException($exception->getMessage(), $exception->getCode(), $exception);
        }

        return new CredentialAttributes(
            $publicKeyCredentialSource->getAttestedCredentialData()->getCredentialId(),
            $publicKeyCredentialSource->getAttestedCredentialData()->getCredentialPublicKey(),
            $publicKeyCredentialSource->getCounter(),
            $publicKeyCredentialSource->getUserHandle(),
            new AuthenticatorTransports(...array_map(
                static fn (string $transport) => AuthenticatorTransport::from($transport),
                $publicKeyCredentialSource->getTransports()
            ))
        );
    }

    /**
     * The PublicKeyCredentialRpEntity dictionary is used to supply additional
     * Relying Party attributes when creating a new credential.
     */
    protected function relyingPartyEntity(): \Webauthn\PublicKeyCredentialRpEntity
    {
        return new \Webauthn\PublicKeyCredentialRpEntity(
            Config::get('laravel-auth.webauthn.relying_party.name'),
            Config::get('laravel-auth.webauthn.relying_party.id')
        );
    }

    /**
     * The PublicKeyCredentialUserEntity dictionary is used to supply additional
     * user account attributes when creating a new credential.
     */
    protected function userEntity(PublicKeyCredentialUserEntity $user): \Webauthn\PublicKeyCredentialUserEntity
    {
        return new \Webauthn\PublicKeyCredentialUserEntity($user->name(), $user->id(), $user->displayName());
    }

    /**
     * The challenge is a buffer of cryptographically random bytes generated on the server,
     * and is needed to prevent "replay attacks".
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge
     *
     * @throws Exception
     */
    protected function generateChallenge(): string
    {
        return random_bytes(16);
    }

    /**
     * This is an array of objects describing what public key types are acceptable to a server.
     * The alg is a described in the COSE registry; for example, -7 indicates that
     * the server accepts ECDSA public keys with a SHA-256 signature algorithm.
     *
     * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams
     *
     * @return \Webauthn\PublicKeyCredentialParameters[]
     */
    protected function publicKeyCredentialParameters(): array
    {
        return Collection::make(Config::get('laravel-auth.webauthn.algorithms', []))
            ->map(fn (COSEAlgorithmIdentifier $algorithm) => new \Webauthn\PublicKeyCredentialParameters(
                \Webauthn\PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $algorithm->value
            ))
            ->all();
    }

    /**
     * The time (in milliseconds) that the user has to respond to a prompt
     * for registration before an error is returned.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout
     */
    protected function timeout(): int
    {
        return Config::get('laravel-auth.webauthn.timeout', 30);
    }

    /**
     * This optional object helps relying parties make further restrictions on the type of authenticators
     * allowed for registration. Examples include cross-platform authenticators (like a Yubikey)
     * instead of platform authenticators like Windows Hello or Apple Passkeys.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection
     */
    protected function multiFactorCredentialAuthenticatorSelectionCriteria(): \Webauthn\AuthenticatorSelectionCriteria
    {
        /** @var AuthenticatorAttachment|null $authenticatorAttachment */
        $authenticatorAttachment = Config::get('laravel-auth.webauthn.multi-factor.authenticator_attachment');

        $selection = \Webauthn\AuthenticatorSelectionCriteria::create();
        $selection->setAuthenticatorAttachment($authenticatorAttachment?->value);
        $selection->setUserVerification(UserVerificationRequirement::DISCOURAGED->value);

        return $selection;
    }

    /**
     * This optional object helps relying parties make further restrictions on the type of authenticators
     * allowed for registration. Examples include cross-platform authenticators (like a Yubikey)
     * instead of platform authenticators like Windows Hello or Apple Passkeys.
     *
     * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection
     */
    protected function passkeyBasedAuthenticatorSelectionCriteria(): \Webauthn\AuthenticatorSelectionCriteria
    {
        /** @var AuthenticatorAttachment|null $authenticatorAttachment */
        $authenticatorAttachment = Config::get('laravel-auth.webauthn.passkeys.authenticator_attachment', AuthenticatorAttachment::PLATFORM);

        $selection = \Webauthn\AuthenticatorSelectionCriteria::create();
        $selection->setAuthenticatorAttachment($authenticatorAttachment?->value);
        $selection->setUserVerification(UserVerificationRequirement::REQUIRED->value);
        $selection->setResidentKey(ResidentKeyRequirement::REQUIRED->value);

        /**
         * This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons, its
         * naming retains the deprecated "resident" terminology for discoverable credentials. Relying Parties
         * SHOULD set it to true if, and only if, residentKey is set to required.
         *
         * @link https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
         */
        $selection->setRequireResidentKey(true);

        return $selection;
    }

    /**
     * Prepares the given public key credentials.
     *
     * @param  \Illuminate\Support\Collection|null  $credentials
     * @return \Webauthn\PublicKeyCredentialDescriptor[]
     */
    protected function prepareCredentials(?Collection $credentials): array
    {
        return ($credentials ?? new Collection())->map(function (CredentialAttributes $credential) {
            return \Webauthn\PublicKeyCredentialDescriptor::create(
                \Webauthn\PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $credential->id(),
                Collection::make($credential->transports()->all())
                    ->map(fn (AuthenticatorTransport $transport) => $transport->value)
                    ->all(),
            );
        })->all();
    }

    /**
     * The attestation data that is returned from the authenticator has information that could be used
     * to track users. This option allows servers to indicate how important the attestation data is
     * to this registration event. A value of "none" indicates that the server does not care
     * about attestation. A value of "indirect" means that the server will allow for
     * anonymized attestation data. "direct" means that the server wishes to
     * receive the attestation data from the authenticator.
     *
     * @link https://www.w3.org/TR/webauthn-2/#attestation-conveyance
     */
    protected function attestation(): string
    {
        /** @var AttestationConveyancePreference $attestation */
        $attestation = Config::get('laravel-auth.webauthn.attestation');

        return $attestation->value;
    }

    /**
     * During the registration of an authenticator, you can ask for the Attestation Statement of the authenticator.
     * The AttestationStatementSupportManager helps the server to understand and validate these statements.
     *
     * @link https://webauthn-doc.spomky-labs.com/webauthn-in-a-nutshell/attestation-and-metadata-statement
     * @link https://webauthn-doc.spomky-labs.com/pure-php/advanced-behaviours/attestation-and-metadata-statement#credential-creation-options
     * @link https://www.w3.org/TR/webauthn-2/#attestation-statement
     */
    protected function getAttestationStatementSupportManager(): AttestationStatementSupportManager
    {
        $attestationStatementSupportManager = new AttestationStatementSupportManager();
        $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
        $attestationStatementSupportManager->add(new AppleAttestationStatementSupport());
        $attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport());
        $attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport());
        $attestationStatementSupportManager->add(new PackedAttestationStatementSupport($this->getAlgorithmManager()));
        $attestationStatementSupportManager->add(new TPMAttestationStatementSupport());

        return $attestationStatementSupportManager;
    }

    /**
     * This object will load the Attestation statements received from the devices.
     * It will need the Attestation Statement Support Manager created above.
     *
     * @link https://webauthn-doc.spomky-labs.com/pure-php/the-hard-way#attestation-object-loader
     */
    protected function getAttestationObjectLoader(): AttestationObjectLoader
    {
        return new AttestationObjectLoader($this->getAttestationStatementSupportManager());
    }

    /**
     * This object will verify and load the public key credential from the Attestation Object.
     *
     * @link https://webauthn-doc.spomky-labs.com/pure-php/the-hard-way#public-key-credential-loader
     */
    protected function getPublicKeyCredentialLoader(): PublicKeyCredentialLoader
    {
        return new PublicKeyCredentialLoader($this->getAttestationObjectLoader());
    }

    /**
     * Verifies and loads the public key credential from the authenticator-signed JSON payload.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     */
    protected function loadPublicKeyCredential(array $credential): PublicKeyCredential
    {
        $loader = $this->getPublicKeyCredentialLoader();

        try {
            $publicKeyCredential = $loader->loadArray($credential);
        } catch (Throwable $exception) {
            throw new InvalidPublicKeyCredentialException($exception->getMessage(), $exception->getCode(), $exception);
        }

        return $publicKeyCredential;
    }

    /**
     * This object will validate the incoming Attestation Response.
     *
     * @link https://www.w3.org/TR/webauthn-2/#registering-a-new-credential
     */
    protected function getAuthenticatorAttestationResponseValidator(): AuthenticatorAttestationResponseValidator
    {
        return new AuthenticatorAttestationResponseValidator(
            $this->getAttestationStatementSupportManager(),
            new PublicKeyCredentialSourceRepository(),
            new IgnoreTokenBindingHandler(), // TODO: Support secure token binding
            new ExtensionOutputCheckerHandler()
        );
    }

    /**
     * This object will validate the incoming Attestation Response.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     */
    protected function getAuthenticatorAssertionResponseValidator(): AuthenticatorAssertionResponseValidator
    {
        return new AuthenticatorAssertionResponseValidator(
            new PublicKeyCredentialSourceRepository(),
            new IgnoreTokenBindingHandler(), // TODO: Support secure token binding
            new ExtensionOutputCheckerHandler(),
            $this->getAlgorithmManager()
        );
    }

    /**
     * The Webauthn data verification is based on cryptographic signatures and thus
     * you need to provide cryptographic algorithms to perform those checks.
     *
     * @link https://webauthn-doc.spomky-labs.com/pure-php/the-hard-way#algorithm-manager
     */
    protected function getAlgorithmManager(): Manager
    {
        return Manager::create()->add(
            ES256::create(),
            ES256K::create(),
            ES384::create(),
            ES512::create(),
            RS256::create(),
            RS384::create(),
            RS512::create(),
            PS256::create(),
            PS384::create(),
            PS512::create(),
            Ed256::create(),
            Ed512::create(),
        );
    }
}
