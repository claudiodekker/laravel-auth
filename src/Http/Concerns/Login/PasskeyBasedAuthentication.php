<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Login;

use App\Models\User;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract as WebAuthn;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Psr\Http\Message\ServerRequestInterface;

trait PasskeyBasedAuthentication
{
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the passkey authentication state is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidPasskeyAuthenticationStateResponse(Request $request);

    /**
     * Initialize the passkey based authentication process by generating challenge details.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions
     */
    protected function initializePasskeyAuthenticationOptions(Request $request): PublicKeyCredentialRequestOptions
    {
        return tap($this->generatePasskeyAuthenticationOptions($request), function ($options) use ($request) {
            $this->setPasskeyAuthenticationOptions($request, $options);
        });
    }

    /**
     * Handle a passkey based authentication request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function handlePasskeyBasedAuthentication(Request $request)
    {
        $this->validatePasskeyBasedRequest($request);

        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitingExpiresInSeconds($request));
        }

        if (! $options = $this->getPasskeyAuthenticationOptions($request)) {
            return $this->sendInvalidPasskeyAuthenticationStateResponse($request);
        }

        try {
            $credential = $this->validatePasskey($request, $options);
        } catch (InvalidPublicKeyCredentialException|UnexpectedActionException) {
            $this->incrementRateLimitingCounter($request);
            $this->emitAuthenticationFailedEvent($request);

            return $this->sendAuthenticationFailedResponse($request);
        }

        $user = $this->resolveUserFromPasskey($request, $credential);

        $this->clearPasskeyAuthenticationOptions($request);
        $this->resetRateLimitingCounter($request);
        $this->authenticate($user, $this->isRememberingUser($request));
        $this->enableSudoMode($request);
        $this->emitAuthenticatedEvent($request, $user);

        return $this->sendAuthenticatedResponse($request, $user);
    }

    /**
     * Validate the passkey based authentication request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePasskeyBasedRequest(Request $request): void
    {
        $request->validate([
            'credential' => 'required',
        ]);
    }

    /**
     * Generate the challenge details used to perform passkey based authentication.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions
     */
    protected function generatePasskeyAuthenticationOptions(Request $request): PublicKeyCredentialRequestOptions
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->generatePasskeyRequestOptions();
    }

    /**
     * Temporarily store the challenge details used to perform passkey based authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions  $options
     * @return void
     */
    protected function setPasskeyAuthenticationOptions(Request $request, PublicKeyCredentialRequestOptions $options): void
    {
        $request->session()->put('auth.login.passkey_authentication_options', serialize($options));
    }

    /**
     * Retrieve the temporarily stored challenge details used to perform passkey based authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions|null
     */
    protected function getPasskeyAuthenticationOptions(Request $request): ?PublicKeyCredentialRequestOptions
    {
        $array = $request->session()->get('auth.login.passkey_authentication_options');
        if ($array === null) {
            return null;
        }

        return unserialize($array, [PublicKeyCredentialRequestOptions::class]);
    }

    /**
     * Clear the temporarily stored challenge details used to perform passkey based authentication.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function clearPasskeyAuthenticationOptions(Request $request): void
    {
        $request->session()->forget('auth.login.passkey_authentication_options');
    }

    /**
     * Validates the signed passkey for the given challenge details.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions  $options
     * @return \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    protected function validatePasskey(Request $request, PublicKeyCredentialRequestOptions $options): CredentialAttributes
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->validateCredential(
            App::make(ServerRequestInterface::class),
            $options
        );
    }

    /**
     * Resolve the User that is being authenticated using the passkey.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes  $credential
     * @return \Illuminate\Contracts\Auth\Authenticatable
     *
     * @throws \Illuminate\Database\Eloquent\ModelNotFoundException
     */
    protected function resolveUserFromPasskey(Request $request, CredentialAttributes $credential): Authenticatable
    {
        return User::query()
            ->where('has_password', false)
            ->findOrFail($credential->userHandle());
    }
}
