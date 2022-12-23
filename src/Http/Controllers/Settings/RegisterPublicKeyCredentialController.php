<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Settings;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract as WebAuthn;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Http\Message\ServerRequestInterface;

abstract class RegisterPublicKeyCredentialController
{
    use EmailBased;

    /**
     * Sends a response that displays the public key registration page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return mixed
     */
    abstract protected function sendRegistrationPageResponse(Request $request, PublicKeyCredentialCreationOptions $options);

    /**
     * Sends a response indicating that the public key credential has been registered.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\MultiFactorCredential  $credential
     * @return mixed
     */
    abstract protected function sendCredentialRegisteredResponse(Request $request, $credential);

    /**
     * Sends a response indicating that the public key credential registration state is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidPublicKeyRegistrationStateResponse(Request $request);

    /**
     * Sends a response indicating that the provided public key credential is not valid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidPublicKeyCredentialResponse(Request $request);

    /**
     * Handle an incoming request to view the public key registration page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendRegistrationPageResponse()
     */
    public function create(Request $request)
    {
        $options = $this->generatePublicKeyRegistrationOptions($request);
        $this->setPublicKeyRegistrationOptions($request, $options);

        return $this->sendRegistrationPageResponse($request, $options);
    }

    /**
     * Complete the registration of a new public key credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendInvalidPublicKeyRegistrationStateResponse()
     * @see static::sendInvalidPublicKeyCredentialResponse()
     * @see static::sendCredentialRegisteredResponse()
     */
    public function store(Request $request)
    {
        $this->validateRegistrationRequest($request);

        if (! $options = $this->getPublicKeyRegistrationOptions($request)) {
            return $this->sendInvalidPublicKeyRegistrationStateResponse($request);
        }

        try {
            $attributes = $this->validateAndPrepareCredentialAttributes($request, $options);
        } catch (InvalidPublicKeyCredentialException|UnexpectedActionException) {
            return $this->sendInvalidPublicKeyCredentialResponse($request);
        }

        $credential = $this->createPublicKeyCredential($request, $attributes);
        $this->clearPublicKeyRegistrationOptions($request);

        return $this->sendCredentialRegisteredResponse($request, $credential);
    }

    /**
     * Generate the challenge details used to register a new public key credential.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions
     */
    protected function generatePublicKeyRegistrationOptions(Request $request): PublicKeyCredentialCreationOptions
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        $user = $request->user();

        return $webAuthn->generatePublicKeyCreationOptions(
            $this->prepareUserEntity($user),
            $this->getExcludedCredentials($user)
        );
    }

    /**
     * Resolve the given user as a public key credential user entity instance.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity
     */
    protected function prepareUserEntity(Authenticatable $user): PublicKeyCredentialUserEntity
    {
        return new PublicKeyCredentialUserEntity(
            $user->getAuthIdentifier(),
            $user->{$this->usernameField()},
            $user->name,
        );
    }

    /**
     * Retrieve all public key credentials for the given user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \Illuminate\Support\Collection
     */
    protected function getExcludedCredentials(Authenticatable $user): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('type', CredentialType::PUBLIC_KEY)
            ->get()
            ->map(fn ($credential) => CredentialAttributes::fromJson($credential->secret));
    }

    /**
     * Temporarily store the challenge details used to register a new public key credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return void
     */
    protected function setPublicKeyRegistrationOptions(Request $request, PublicKeyCredentialCreationOptions $options): void
    {
        $request->session()->put('auth.mfa_setup.public_key_credential_creation_options', serialize($options));
    }

    /**
     * Retrieve the temporarily stored challenge details used to register a new public key credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions|null
     */
    protected function getPublicKeyRegistrationOptions(Request $request): ?PublicKeyCredentialCreationOptions
    {
        $array = $request->session()->get('auth.mfa_setup.public_key_credential_creation_options');
        if ($array === null) {
            return null;
        }

        return unserialize($array, [PublicKeyCredentialCreationOptions::class]);
    }

    /**
     * Clear the temporarily stored challenge details used to register a new public key credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function clearPublicKeyRegistrationOptions(Request $request)
    {
        $request->session()->forget('auth.mfa_setup.public_key_credential_creation_options');
    }

    /**
     * Validate the public key credential registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateRegistrationRequest(Request $request): void
    {
        $request->validate([
            'name' => 'required|string',
            'credential' => 'required',
        ]);
    }

    /**
     * Validates the signed public key credential for the given challenge details.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes
     */
    protected function validateAndPrepareCredentialAttributes(Request $request, PublicKeyCredentialCreationOptions $options): CredentialAttributes
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->getAttestedCredentialAttributes(
            App::make(ServerRequestInterface::class),
            $options,
        );
    }

    /**
     * Creates the new public key credential for the current user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes  $attributes
     * @return \ClaudioDekker\LaravelAuth\MultiFactorCredential
     */
    protected function createPublicKeyCredential(Request $request, CredentialAttributes $attributes)
    {
        return LaravelAuth::multiFactorCredential()->query()->create([
            'id' => CredentialType::PUBLIC_KEY->value.'-'.Base64UrlSafe::encodeUnpadded($attributes->id()),
            'type' => CredentialType::PUBLIC_KEY,
            'user_id' => Auth::id(),
            'name' => $request->input('name'),
            'secret' => $attributes->toJson(),
        ]);
    }
}
