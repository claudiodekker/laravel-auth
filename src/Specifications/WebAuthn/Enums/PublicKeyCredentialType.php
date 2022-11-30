<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enum-credentialType
 */
enum PublicKeyCredentialType: string
{
    case PUBLIC_KEY = 'public-key';
}
