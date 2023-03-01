<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Login;

use App\Models\User;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract as WebAuthn;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Http\Message\ServerRequestInterface;

trait PasskeyBasedAuthentication
{
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the passkey authentication state is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidPasskeyAuthenticationStateResponse(Request $request);

    /**
     * Initialize the passkey based authentication process by generating challenge details.
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
     * @return mixed
     */
    protected function handlePasskeyBasedAuthentication(Request $request)
    {
        $this->validatePasskeyBasedRequest($request);

        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
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
        $this->updatePasskeyCredential($request, $credential);
        $this->authenticate($user, $this->isRememberingUser($request));
        $this->enableSudoMode($request);
        $this->emitAuthenticatedEvent($request, $user);

        return $this->sendAuthenticatedResponse($request, $user);
    }

    /**
     * Validate the passkey based authentication request.
     *
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
     * Update the passkey credential using the latest attributes, such as the signature counter.
     */
    protected function updatePasskeyCredential(Request $request, CredentialAttributes $attributes): void
    {
        LaravelAuth::multiFactorCredential()->query()
            ->where('type', CredentialType::PUBLIC_KEY->value)
            ->findOrFail(CredentialType::PUBLIC_KEY->value.'-'.Base64UrlSafe::encodeUnpadded($attributes->id()))
            ->update(['secret' => $attributes->toJson()]);
    }

    /**
     * Generate the challenge details used to perform passkey based authentication.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     */
    protected function generatePasskeyAuthenticationOptions(Request $request): PublicKeyCredentialRequestOptions
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->generatePasskeyRequestOptions();
    }

    /**
     * Temporarily store the challenge details used to perform passkey based authentication.
     */
    protected function setPasskeyAuthenticationOptions(Request $request, PublicKeyCredentialRequestOptions $options): void
    {
        $request->session()->put('auth.login.passkey_authentication_options', serialize($options));
    }

    /**
     * Retrieve the temporarily stored challenge details used to perform passkey based authentication.
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
     */
    protected function clearPasskeyAuthenticationOptions(Request $request): void
    {
        $request->session()->forget('auth.login.passkey_authentication_options');
    }

    /**
     * Validates the signed passkey for the given challenge details.
     *
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
