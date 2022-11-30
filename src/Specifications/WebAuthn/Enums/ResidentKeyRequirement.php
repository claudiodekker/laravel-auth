<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement
 */
enum ResidentKeyRequirement: string
{
    case DISCOURAGED = 'discouraged';
    case PREFERRED = 'preferred';
    case REQUIRED = 'required';
}
