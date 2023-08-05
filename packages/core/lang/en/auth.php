<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Authentication Language Lines
    |--------------------------------------------------------------------------
    |
    | The following language lines are used during authentication for various
    | messages that we need to display to the user. You are free to modify
    | these language lines according to your application's requirements.
    |
    */

    'failed' => 'These credentials do not match our records.',
    'password' => 'The provided password is incorrect.',
    'throttle' => 'Too many login attempts. Please try again in :seconds seconds.',

    'success' => 'You have been successfully authenticated.',
    'challenge' => [
        'public-key' => 'The provided public key credential is incorrect.',
        'recovery' => 'The provided recovery code is incorrect.',
        'throttle' => 'Too many confirmation attempts. Please try again in :seconds seconds.',
        'totp' => 'The provided one-time-password code is incorrect.',
    ],
    'settings' => [
        'credential-deleted' => 'The multi-factor credential has been deleted.',
        'password-changed' => 'Your password has been changed successfully.',
        'public-key-registered' => 'Public key credential successfully registered.',
        'recovery-configured' => 'Account recovery codes successfully configured.',
        'totp-registered' => 'Time-based one-time-password credential successfully registered.',
    ],
    'recovery' => [
        'sent' => 'If the provided email address is associated with an account, you will receive a recovery link shortly.',
        'invalid' => 'The provided email and recovery token combination are invalid.',
        'throttle' => 'Too many recovery requests. Please try again in :seconds seconds.',
    ],
    'verification' => [
        'already-verified' => 'Your email address has already been verified.',
        'sent' => 'A verification link has been sent to the email address you provided during registration.',
        'verified' => 'Your email address has been verified.',
    ],
    'security-indicator' => [
        'no-mfa-no-recovery-codes' => 'Your account is vulnerable. Please enable multi-factor authentication and set up account recovery codes.',
        'no-mfa-has-recovery-codes' => 'Your account is vulnerable without multi-factor authentication. Please enable it to secure your account.',
        'has-mfa-no-recovery-codes' => 'Your account could be compromised if someone gains access to your email account. Protect yourself by setting up account recovery codes.',
        'has-mfa-has-recovery-codes' => 'Your account is well-protected.',
    ],
];
