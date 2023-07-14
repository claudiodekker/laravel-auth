<?php

namespace ClaudioDekker\LaravelAuth\Http\Concerns\Challenges;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Http\Concerns\InteractsWithRateLimiting;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Contracts\WebAuthnContract as WebAuthn;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException;
use ClaudioDekker\LaravelAuth\Methods\WebAuthn\Objects\CredentialAttributes;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialRequestOptions;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Dictionaries\PublicKeyCredentialUserEntity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\App;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Psr\Http\Message\ServerRequestInterface;

trait PublicKeyChallenge
{
    use InteractsWithRateLimiting;

    /**
     * Sends a response indicating that the public key challenge state is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidPublicKeyChallengeStateResponse(Request $request);

    /**
     * Sends a response indicating that the public key challenge did not succeed.
     *
     * @return mixed
     */
    abstract protected function sendPublicKeyChallengeFailedResponse(Request $request);

    /**
     * Sends a response indicating that the public key challenge has succeeded.
     *
     * @return mixed
     */
    abstract protected function sendPublicKeyChallengeSuccessfulResponse(Request $request);

    /**
     * Resolve the User instance that the challenge is for.
     */
    protected function resolveUser(Request $request): Authenticatable
    {
        return $request->user();
    }

    /**
     * Handle the generation and initialization of the public key challenge details.
     *
     * When no credentials are found, NULL will be returned, indicating that the challenge is not available.
     */
    protected function handlePublicKeyChallengeInitialization(Request $request, Collection $allowedCredentials = null): ?PublicKeyCredentialRequestOptions
    {
        $credentials = $allowedCredentials ?? $this->getPublicKeyCredentials($this->resolveUser($request));
        if ($credentials->isEmpty()) {
            return null;
        }

        return tap($this->generatePublicKeyChallengeOptions($request, $credentials), function ($options) use ($request) {
            $this->setPublicKeyChallengeOptions($request, $options);
        });
    }

    /**
     * Invalidates the challenge details used to perform the public key challenge confirmation.
     */
    protected function handlePublicKeyChallengeInvalidation(Request $request): void
    {
        $request->session()->forget($this->publicKeyChallengeOptionsKey($request));
    }

    /**
     * Handle a public key challenge confirmation request.
     *
     * @return mixed
     */
    protected function handlePublicKeyChallengeRequest(Request $request)
    {
        $this->validatePublicKeyChallengeRequest($request);

        if ($this->isCurrentlyRateLimited($request)) {
            $this->emitLockoutEvent($request);

            return $this->sendRateLimitedResponse($request, $this->rateLimitExpiresInSeconds($request));
        }

        if (! $options = $this->getPublicKeyChallengeOptions($request)) {
            return $this->sendInvalidPublicKeyChallengeStateResponse($request);
        }

        try {
            $credential = $this->validatePublicKeyCredential($request, $options);
        } catch (InvalidPublicKeyCredentialException|UnexpectedActionException) {
            $this->incrementRateLimitingCounter($request);

            return $this->sendPublicKeyChallengeFailedResponse($request);
        }

        $this->handlePublicKeyChallengeInvalidation($request);
        $this->resetRateLimitingCounter($request);
        $this->updatePublicKeyCredential($request, $credential);

        return $this->sendPublicKeyChallengeSuccessfulResponse($request);
    }

    /**
     * Validate the public key challenge confirmation request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validatePublicKeyChallengeRequest(Request $request): void
    {
        $request->validate([
            'credential' => 'required',
        ]);
    }

    /**
     * Retrieve all active public key credentials for the given user.
     */
    protected function getPublicKeyCredentials(Authenticatable $user): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('type', CredentialType::PUBLIC_KEY->value)
            ->where('user_id', $user->getAuthIdentifier())
            ->get()
            ->map(fn ($credential) => CredentialAttributes::fromJson($credential->secret));
    }

    /**
     * Update the public key credential using the latest attributes, such as the signature counter.
     */
    protected function updatePublicKeyCredential(Request $request, CredentialAttributes $attributes): void
    {
        LaravelAuth::multiFactorCredential()->query()
            ->where('type', CredentialType::PUBLIC_KEY->value)
            ->findOrFail(CredentialType::PUBLIC_KEY->value.'-'.Base64UrlSafe::encodeUnpadded($attributes->id()))
            ->update(['secret' => $attributes->toJson()]);
    }

    /**
     * Generate the challenge details used to perform the public key challenge.
     *
     * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
     */
    protected function generatePublicKeyChallengeOptions(Request $request, Collection $allowedCredentials): PublicKeyCredentialRequestOptions
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->generatePublicKeyRequestOptions($allowedCredentials);
    }

    /**
     * Determine the identifier used to track the public key challenge options state.
     */
    protected function publicKeyChallengeOptionsKey(Request $request): string
    {
        return 'laravel-auth::public_key_challenge_request_options';
    }

    /**
     * Temporarily store the challenge details used to perform the public key challenge confirmation.
     */
    protected function setPublicKeyChallengeOptions(Request $request, PublicKeyCredentialRequestOptions $options): void
    {
        $request->session()->put($this->publicKeyChallengeOptionsKey($request), serialize($options));
    }

    /**
     * Retrieve the temporarily stored challenge details used to perform the public key challenge confirmation.
     */
    protected function getPublicKeyChallengeOptions(Request $request): ?PublicKeyCredentialRequestOptions
    {
        $array = $request->session()->get($this->publicKeyChallengeOptionsKey($request));
        if ($array === null) {
            return null;
        }

        return unserialize($array, [PublicKeyCredentialRequestOptions::class]);
    }

    /**
     * Resolve the given user as a public key credential user entity instance.
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
     * Validates the signed public key credential for the given public key challenge details.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\InvalidPublicKeyCredentialException
     * @throws \ClaudioDekker\LaravelAuth\Methods\WebAuthn\Exceptions\UnexpectedActionException
     */
    protected function validatePublicKeyCredential(Request $request, PublicKeyCredentialRequestOptions $options): CredentialAttributes
    {
        /** @var WebAuthn $webAuthn */
        $webAuthn = App::make(WebAuthn::class);

        return $webAuthn->validateCredential(
            App::make(ServerRequestInterface::class),
            $options,
            $this->prepareUserEntity($this->resolveUser($request)),
        );
    }
}
