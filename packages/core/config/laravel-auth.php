<?php

use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AttestationConveyancePreference;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment;
use ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\COSEAlgorithmIdentifier;
use Illuminate\Support\Str;

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Auth Public Key Credential Settings (WebAuthn)
    |--------------------------------------------------------------------------
    |
    | These options are used to configure the WebAuthn service, which allows
    | your application to utilize registration and authentication through
    | the WebAuthn / FIDO2 protocol (Passkeys, YubiKeys etc.)
    |
    | @link https://webauthn.guide/#about-webauthn
    |
    */
    'webauthn' => [

        /**
         * These options are used to configure the Relying Party, which represents
         * your organization in the context of this application, and gets used
         * when an user authenticates using WebAuthn (Security Keys).
         *
         * Please note that changing these after users have registered tokens
         * with your application can lead to authorization problems.
         *
         * @link https://www.w3.org/TR/webauthn-2/#webauthn-relying-party
         */
        'relying_party' => [
            /**
             * The domain of the application without the scheme, userinfo, port, path etc.
             * Allowed formats: www.sub.domain.com, sub.domain.com, domain.com
             */
            'id' => env('AUTH_RP_ID', Str::after(config('app.url'), '://')),

            /**
             * The name of your application.
             */
            'name' => env('AUTH_RP_NAME', config('app.name', 'Laravel')),
        ],

        /**
         * These option is only intended for development purposes, and should not be used in production environment.
         * It is important for scenarios where you want to test the WebAuthn flow on localhost, but you don't have
         * a valid SSL certificate. In this case, you can use this option to bypass the SSL requirement.
         */
        'secured_relying_parties' => 
            env('AUTH_RP_ID', Str::after(config('app.url'), '://')) === 'localhost' && env('APP_ENV') === 'local'
                ? ['localhost']
                : [],

        /**
         * These options are used to configure the preferences for multi-factor authentication.
         *
         * In contrast to Passkeys (or client-side discoverable credentials), the credentials used during
         * multi-factor authentication are server-side credentials. This means that the credentials are
         * stored on the server, and not on the client's (often storage-constrained) authenticator.
         *
         * @link https://www.w3.org/TR/webauthn-2/#server-side-public-key-credential-source
         */
        'multi-factor' => [
            /**
             * This option filters / limits eligible authenticator by type.
             *
             * - The value "platform" indicates a platform authenticator, such as Windows Hello or Apple Passkeys.
             * - The value "cross-platform" value indicates a roaming authenticator, such as a YubiKey device.
             *
             * For server-side generated credentials, we don't have a preference, as the credential isn't
             * being stored on the authenticator itself, so we're not unnecessarily taking up space.
             *
             * @link https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/WebAuthn_Client_Registration.html
             * @link https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality
             * @link https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
             * @see \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment
             */
            'authenticator_attachment' => null,
        ],

        /**
         * These options are used to configure the preferences for Passkey / passwordless authentication.
         *
         * In contrast to multi-factor authentication (or server-side credentials), Passkey credentials are
         * essentially a rebranding of client-side discoverable credentials / resident key credentials.
         *
         * While client-side discoverable credentials are stored on the client's authenticator, which is
         * often storage-constrained, most Passkeys are part of the user's phone or laptop instead of
         * being a separate hardware authenticator such as a YubiKey. This means that they do not
         * suffer from this storage limitation, and are very suitable to replace passwords.
         *
         * @link https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential
         * @link https://www.yubico.com/blog/a-yubico-faq-about-passkeys/
         */
        'passkeys' => [
            /**
             * This option filters / limits the eligible authenticators by type.
             *
             * - The value "platform" indicates a platform authenticator, such as Windows Hello or Apple Passkeys.
             * - The value "cross-platform" value indicates a roaming authenticator, such as a YubiKey device.
             *
             * Since client-side credentials are stored on the authenticator itself, we'll likely want to
             * restrict the type of authenticator that can be used, as to not take any (limited) space.
             *
             * As an example, a cross-platform YubiKey (as of July 2022) can only store up to 25 Passkeys.
             * Simultaneously, a platform authenticator such as iOS 16, does not have a defined limit.
             *
             * @link https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/WebAuthn_Client_Registration.html
             * @link https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality
             * @link https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
             * @see \ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums\AuthenticatorAttachment
             */
            'authenticator_attachment' => AuthenticatorAttachment::PLATFORM,
        ],

        /**
         * The time (in milliseconds) that the user has to respond to a action prompt before an error is returned.
         *
         * Depending on the configured user_verification value, there are different official recommendations:
         * - REQUIRED or PREFERRED: Between 30000ms and 600000ms (default: 300000ms).
         * - DISCOURAGED: Between 30000ms and 180000ms (default: 120000ms).
         *
         * Inspired by several online platforms, this library maintains the lower-end 30000ms value as it's default.
         *
         * @link https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout
         * @link https://www.w3.org/TR/webauthn-2/#sctn-createCredential
         */
        'timeout' => 30000,

        /**
         * The attestation data that is returned from the authenticator has information that could be used
         * to track users. This option allows servers to indicate how important the attestation data is
         * to this registration event.
         *
         * - A value of "none" indicates that the server does not care about attestation.
         * - A value of "indirect" means that the server will allow for anonymized attestation data.
         * - A value of "direct" means that the server wishes to receive the attestation data from the authenticator.
         *
         * @link https://www.w3.org/TR/webauthn-2/#attestation-conveyance
         */
        'attestation' => AttestationConveyancePreference::NONE,

        /**
         * The cryptographic algorithm used to generate a public keypair during a FIDO2/WebAuthn registration is
         * determined by the capabilities of the FIDO2 Authenticator and the preferences of the RP (this Laravel app).
         *
         * The COSE Algorithms registry contains definitions of all possible algorithms that can be used.
         * This is enforced due to some transports, such as Bluetooth or NFC, having restrictions in data bandwidth
         * that make transmission of JSON files problematic. To avoid this issue, FIDO2 interactions must be
         * capable of being translated to the CBOR format, including the algorithms utilized.
         *
         * The RP will further narrow down the supported algorithms, depending on those supported by the FIDO2 server.
         *
         * @link https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/Algorithms.html
         * @link https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
         * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
         */
        'algorithms' => [
            COSEAlgorithmIdentifier::ES256,
            COSEAlgorithmIdentifier::RS256,
            // COSEAlgorithmIdentifier::EdDSA,
            // COSEAlgorithmIdentifier::ES384,
            // COSEAlgorithmIdentifier::ES512,
            // COSEAlgorithmIdentifier::PS256,
            // COSEAlgorithmIdentifier::PS384,
            // COSEAlgorithmIdentifier::PS512,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Sudo Mode Expiration Timeout
    |--------------------------------------------------------------------------
    |
    | Here you may define the amount of seconds that the user can idle before
    | sudo-mode expires, and the user is prompted to confirm access again.
    | This is useful for extra secure sections of your app, such as the
    | user's account settings, or a dedicated admin-only dashboard.
    |
    */
    'sudo_mode_duration' => env('SUDO_MODE_DURATION', 900),
];
