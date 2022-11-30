<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Registration;

use App\Models\User;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract as WebAuthn;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Http\Message\ServerRequestInterface;

trait PasskeyBasedRegistration
{
    /**
     * Sends a response indicating that the passkey-based registration process has been initialized.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return mixed
     */
    abstract protected function sendPasskeyBasedRegistrationInitializedResponse(Request $request, PublicKeyCredentialCreationOptions $options);

    /**
     * Sends a response indicating that the passkey-based registration state is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidPasskeyRegistrationStateResponse(Request $request);

    /**
     * Sends a response indicating that the signed passkey is not valid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidPasskeyResponse(Request $request);

    /**
     * Handle a passkey based registration request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function handlePasskeyBasedRegistration(Request $request)
    {
        if (! $this->isPasskeyConfirmationRequest($request)) {
            return $this->initializePasskeyRegistration($request);
        }

        return $this->confirmPasskeyBasedRegistration($request);
    }

    /**
     * Initialize the passkey based registration process.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function initializePasskeyRegistration(Request $request)
    {
        $this->validatePasskeyBasedInitializationRequest($request);

        $user = $this->claimPasswordlessUser($request);

        $options = $this->generatePasskeyCreationOptions($request, $user);
        $this->setPasskeyCreationOptions($request, $options);

        return $this->sendPasskeyBasedRegistrationInitializedResponse($request, $options);
    }

    /**
     * Finalize the passkey based registration process.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function confirmPasskeyBasedRegistration(Request $request)
    {
        if (! $options = $this->getPasskeyCreationOptions($request)) {
            return $this->sendInvalidPasskeyRegistrationStateResponse($request);
        }

        try {
            $attributes = $this->validateAndPrepareCredentialAttributes($request, $options);
        } catch (InvalidPublicKeyCredentialException|UnexpectedActionException) {
            return $this->sendInvalidPasskeyResponse($request);
        }

        $user = $this->resolveUserFromPasskeyCreationOptions($options);

        $this->createPasskey($request, $user, $attributes);

        $this->clearPasskeyCreationOptions($request);
        $this->emitRegisteredEvent($user);
        $this->sendEmailVerificationNotification($user);
        $this->authenticate($user);
        $this->enableSudoMode($request);

        return $this->sendRegisteredResponse($request, $user);
    }

    /**
     * Determine if the given request is a passkey-based registration confirmation request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function isPasskeyConfirmationRequest(Request $request): bool
    {
        return $request->has('credential');
    }

    /**
     * Validate the passkey-based registration initialization request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasskeyBasedInitializationRequest(Request $request): void
    {
        $request->validate([
            ...$this->registrationValidationRules(),
            'name' => ['required', 'string', 'max:255'],
        ]);
    }

    /**
     * Claims (read: creates) a passkey-based user account.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function claimPasswordlessUser(Request $request): Authenticatable
    {
        return User::create([
            'email' => $request->input('email'),
            $this->usernameField() => $request->input($this->usernameField()),
            'name' => $request->name,
            'password' => Hash::make(Str::uuid()),
            'has_password' => false,
        ]);
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
     * Generate the challenge details used to perform passkey-based registration.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions
     */
    protected function generatePasskeyCreationOptions(Request $request, Authenticatable $user): PublicKeyCredentialCreationOptions
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->generatePasskeyCreationOptions(
            $this->prepareUserEntity($user)
        );
    }

    /**
     * Temporarily store the challenge details used to perform passkey based registration.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return void
     */
    protected function setPasskeyCreationOptions(Request $request, PublicKeyCredentialCreationOptions $options): void
    {
        $request->session()->put('auth.register.passkey_creation_options', serialize($options));
    }

    /**
     * Retrieve the temporarily stored challenge details used to perform passkey based registration.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions|null
     */
    protected function getPasskeyCreationOptions(Request $request): ?PublicKeyCredentialCreationOptions
    {
        $array = $request->session()->get('auth.register.passkey_creation_options');
        if ($array === null) {
            return null;
        }

        return unserialize($array, [PublicKeyCredentialCreationOptions::class]);
    }

    /**
     * Validates the signed passkey for the given challenge details.
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
     * Resolve the User that is being registered from the passkey creation options.
     *
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialCreationOptions  $options
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function resolveUserFromPasskeyCreationOptions(PublicKeyCredentialCreationOptions $options): Authenticatable
    {
        return User::findOrFail($options->user()->id());
    }

    /**
     * Attaches the passkey to the passwordless user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes  $attributes
     * @return \ClaudioDekker\LaravelAuth\MultiFactorCredential
     */
    protected function createPasskey(Request $request, Authenticatable $user, CredentialAttributes $attributes)
    {
        return LaravelAuth::multiFactorCredential()->query()->create([
            'id' => CredentialType::PUBLIC_KEY->value.'-'.Base64UrlSafe::encodeUnpadded($attributes->id()),
            'type' => CredentialType::PUBLIC_KEY,
            'user_id' => $user->getAuthIdentifier(),
            'name' => 'User Passkey',
            'secret' => $attributes->toJson(),
        ]);
    }

    /**
     * Clear the temporarily stored challenge details used to perform passkey based authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function clearPasskeyCreationOptions(Request $request)
    {
        $request->session()->forget('auth.register.passkey_creation_options');
    }
}
