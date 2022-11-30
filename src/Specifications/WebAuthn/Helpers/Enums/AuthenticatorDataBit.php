<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Helpers\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#flags
 */
enum AuthenticatorDataBit: int
{
    case USER_PRESENT = 0b00000001;
    case RESERVED_FUTURE_USE_RFU1 = 0b00000010;
    case USER_VERIFIED = 0b00000100;
    case RESERVED_FUTURE_USE_RFU2 = 0b00111000;
    case ATTESTED_CREDENTIAL_DATA = 0b01000000;
    case EXTENSION_DATA_INCLUDED = 0b10000000;
}
