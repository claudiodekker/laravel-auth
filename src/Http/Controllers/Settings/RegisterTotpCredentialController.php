<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Settings;

use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\Http\Traits\EmailBased;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract as Totp;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

abstract class RegisterTotpCredentialController
{
    use EmailBased;

    /**
     * Sends a response indicating that the time-based one-time-password registration has been initialized.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return mixed
     */
    abstract protected function sendRegistrationInitializedResponse(Request $request, string $secret);

    /**
     * Sends a response that displays the time-based one-time-password confirmation page.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return mixed
     */
    abstract protected function sendConfirmationPageResponse(Request $request, string $secret);

    /**
     * Sends a response indicating that the time-based one-time-password credential has been registered.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \ClaudioDekker\LaravelAuth\MultiFactorCredential  $credential
     * @return mixed
     */
    abstract protected function sendCredentialRegisteredResponse(Request $request, $credential);

    /**
     * Sends a response indicating that the time-based one-time-password credential registration has been cancelled.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendRegistrationCancelledResponse(Request $request);

    /**
     * Sends a response indicating that the time-based one-time-password registration state is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidRegistrationStateResponse(Request $request);

    /**
     * Sends a response indicating that the provided confirmation code is invalid.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendInvalidConfirmationCodeResponse(Request $request);

    /**
     * Initialize the registration of a new time-based one-time-password credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException
     *
     * @see static::sendRegistrationInitializedResponse()
     */
    public function initialize(Request $request)
    {
        $this->setPendingTotpSecret($request, $secret = $this->generateTotpSecret());

        return $this->sendRegistrationInitializedResponse($request, $secret);
    }

    /**
     * Display the view for confirming the time-based one-time-password credential registration.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendInvalidRegistrationStateResponse()
     * @see static::sendConfirmationPageResponse()
     */
    public function confirm(Request $request)
    {
        if (! $secret = $this->getPendingTotpSecret($request)) {
            return $this->sendInvalidRegistrationStateResponse($request);
        }

        return $this->sendConfirmationPageResponse($request, $secret);
    }

    /**
     * Confirm and finalize the registration of the time-based one-time-password credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendInvalidRegistrationStateResponse()
     * @see static::sendInvalidConfirmationCodeResponse()
     * @see static::sendCredentialRegisteredResponse()
     */
    public function store(Request $request)
    {
        $this->validateConfirmationRequest($request);

        if (! $secret = $this->getPendingTotpSecret($request)) {
            return $this->sendInvalidRegistrationStateResponse($request);
        }

        if (! $this->hasValidConfirmationCode($request, $secret)) {
            return $this->sendInvalidConfirmationCodeResponse($request);
        }

        $credential = $this->createTotpCredential($request, $secret);
        $this->clearPendingTotpSecret($request);

        return $this->sendCredentialRegisteredResponse($request, $credential);
    }

    /**
     * Cancel the registration of the time-based one-time-password credential.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendRegistrationCancelledResponse()
     */
    public function cancel(Request $request)
    {
        $this->clearPendingTotpSecret($request);

        return $this->sendRegistrationCancelledResponse($request);
    }

    /**
     * Validate the time-based one-time-password confirmation request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateConfirmationRequest(Request $request): void
    {
        $request->validate([
            'name' => 'required|string',
            'code' => 'required|string|size:6',
        ]);
    }

    /**
     * Determine whether the request contains a valid time-based one-time-password confirmation code.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return bool
     */
    protected function hasValidConfirmationCode(Request $request, string $secret): bool
    {
        /** @var Totp $authenticator */
        $authenticator = App::make(Totp::class);

        return $authenticator->verify(Auth::id(), $secret, $request->input('code'));
    }

    /**
     * Creates the new time-based one-time password credential for the current user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return \ClaudioDekker\LaravelAuth\MultiFactorCredential
     */
    protected function createTotpCredential(Request $request, string $secret)
    {
        return LaravelAuth::multiFactorCredential()->query()->create([
            'id' => CredentialType::TOTP->value.'-'.Str::uuid(),
            'type' => CredentialType::TOTP,
            'user_id' => Auth::id(),
            'name' => $request->input('name'),
            'secret' => $secret,
        ]);
    }

    /**
     * Generate a fresh time-based one-time-password credential secret.
     *
     * @return string
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException
     */
    protected function generateTotpSecret(): string
    {
        /** @var Totp $authenticator */
        $authenticator = App::make(Totp::class);

        return $authenticator->generateSecret();
    }

    /**
     * Generates a scannable, time-based one-time-password setup QR Code SVG for the current user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return string
     */
    protected function generateSetupQrImage(Request $request, string $secret): string
    {
        /** @var Totp $authenticator */
        $authenticator = App::make(Totp::class);

        return $authenticator->toQrImage(
            $secret,
            $request->user()->{$this->usernameField()},
        )->svgData();
    }

    /**
     * Store the pending time-based one-time-password credential secret.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $secret
     * @return void
     */
    protected function setPendingTotpSecret(Request $request, string $secret): void
    {
        $request->session()->put('auth.mfa_setup.pending_totp_secret', $secret);
    }

    /**
     * Retrieve the pending time-based one-time-password credential secret.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string|null
     */
    protected function getPendingTotpSecret(Request $request): ?string
    {
        return $request->session()->get('auth.mfa_setup.pending_totp_secret');
    }

    /**
     * Clear the pending time-based one-time-password credential secret.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function clearPendingTotpSecret(Request $request): void
    {
        $request->session()->forget('auth.mfa_setup.pending_totp_secret');
    }
}
