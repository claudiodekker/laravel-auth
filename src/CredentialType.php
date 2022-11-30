<?php

namespace ClaudioDekker\LaravelAuth;

/**
 * Based on https://w3c.github.io/webappsec-credential-management/#sctn-cred-type-registry
 */
enum CredentialType: string
{
    case TOTP = 'totp';
    case PUBLIC_KEY = 'public-key';
}
