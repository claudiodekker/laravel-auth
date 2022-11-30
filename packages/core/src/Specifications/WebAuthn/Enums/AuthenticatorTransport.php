<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport
 */
enum AuthenticatorTransport: string
{
    case USB = 'usb';
    case NFC = 'nfc';
    case BLE = 'ble';
    case INTERNAL = 'internal';
}
