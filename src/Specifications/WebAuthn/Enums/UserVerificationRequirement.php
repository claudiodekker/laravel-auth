<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
 */
enum UserVerificationRequirement: string
{
    case REQUIRED = 'required';
    case PREFERRED = 'preferred';
    case DISCOURAGED = 'discouraged';
}
