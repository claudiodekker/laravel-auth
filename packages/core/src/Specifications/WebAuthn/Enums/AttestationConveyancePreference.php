<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference
 */
enum AttestationConveyancePreference: string
{
    case NONE = 'none';
    case INDIRECT = 'indirect';
    case DIRECT = 'direct';
    case ENTERPRISE = 'enterprise';
}
