<?php

namespace ClaudioDekker\LaravelAuth\Methods\Totp\Contracts;

use ClaudioDekker\LaravelAuth\Support\QrImage;

interface TotpContract
{
    /**
     * Generate a fresh time-based one-time-password secret.
     *
     * @throws \ClaudioDekker\LaravelAuth\Methods\Totp\Exceptions\InvalidSecretException
     */
    public function generateSecret(): string;

    /**
     * Verify whether the given time-based one-time-password is valid for the given secret.
     * If the code is valid, we'll mark it as used as to prevent replay attacks.
     *
     * @param  int  $userId
     */
    public function verify(mixed $userId, string $secret, string $code): bool;

    /**
     * Generate a QR Code Image instance for the given secret and owner.
     */
    public function toQrImage(string $secret, string $holder): QrImage;
}
