<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
 * @link https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality
 */
enum AuthenticatorAttachment: string
{
    case PLATFORM = 'platform';
    case CROSS_PLATFORM = 'cross-platform';
}
