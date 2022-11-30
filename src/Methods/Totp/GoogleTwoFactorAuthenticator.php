<?php

namespace ClaudioDekker\LaravelAuth\Methods\Totp;

use ClaudioDekker\LaravelAuth\Methods\Totp\Contracts\TotpContract;
use ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException;
use ClaudioDekker\LaravelAuth\Support\QrImage;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Config;
use PragmaRX\Google2FA\Exceptions\Google2FAException;
use PragmaRX\Google2FA\Google2FA;
use Psr\SimpleCache\CacheException;

class GoogleTwoFactorAuthenticator implements TotpContract
{
    /**
     * Create a new Authenticator instance.
     *
     * @param  \PragmaRX\Google2FA\Google2FA  $engine
     * @param  \Illuminate\Contracts\Cache\Repository  $cache
     */
    public function __construct(
        protected Google2FA $engine,
        protected Repository $cache
    ) {
        //
    }

    /**
     * Generate a fresh time-based one-time-password secret.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException
     */
    public function generateSecret(): string
    {
        try {
            return $this->engine->generateSecretKey(32);
        } catch (Google2FAException $e) {
            throw new InvalidSecretException($e->getMessage());
        }
    }

    /**
     * Verify whether the given time-based one-time-password is valid for the given secret.
     * If the code is valid, we'll mark it as used as to prevent replay attacks.
     *
     * @param  int  $userId
     * @param  string  $secret
     * @param  string  $code
     * @return bool
     */
    public function verify(mixed $userId, string $secret, string $code): bool
    {
        $cacheKey = 'auth.mfa.totp_timestamps.'.$userId;

        try {
            $timestamp = $this->engine->verifyKeyNewer($secret, $code, $this->cache->get($cacheKey));
        } catch (Google2FAException|CacheException) {
            return false;
        }

        if ($timestamp === false) {
            return false;
        }

        $this->cache->put($cacheKey, $timestamp, $this->engine->getWindow() * 60);

        return true;
    }

    /**
     * Generate a QR Code Image instance for the given secret and owner.
     *
     * @param  string  $secret
     * @param  string  $holder
     * @return \ClaudioDekker\LaravelAuth\Support\QrImage
     */
    public function toQrImage(string $secret, string $holder): QrImage
    {
        $url = $this->engine->getQRCodeUrl(
            Config::get('app.name'),
            $holder,
            $secret,
        );

        return QrImage::make($url);
    }

    /**
     * Generates a currently valid time-based one-time-password for the given secret.
     * This method is only intended to be used within your tests.
     *
     * @param  string  $secret
     * @return string
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException
     */
    public function testCode(string $secret): string
    {
        try {
            return $this->engine->getCurrentOtp($secret);
        } catch (Google2FAException $e) {
            throw new InvalidSecretException($e->getMessage());
        }
    }
}
