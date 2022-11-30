<?php

namespace ClaudioDekker\LaravelAuth\Specifications\WebAuthn\Enums;

/**
 * @link https://www.w3.org/TR/webauthn-2/#typedefdef-cosealgorithmidentifier
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum COSEAlgorithmIdentifier: int
{
    case AES_CCM_64_128_256 = 33;
    case AES_CCM_64_128_128 = 32;
    case AES_CCM_16_128_256 = 31;
    case AES_CCM_16_128_128 = 30;
    case AES_MAC_256_128 = 26;
    case AES_MAC_128_128 = 25;
    case CHACHA20_POLY1305 = 24;
    case AES_MAC_256_64 = 15;
    case AES_MAC_128_64 = 14;
    case AES_CCM_64_64_256 = 13;
    case AES_CCM_64_64_128 = 12;
    case AES_CCM_16_64_256 = 11;
    case AES_CCM_16_64_128 = 10;
    case HS512 = 7;
    case HS384 = 6;
    case HS256 = 5;
    case HS256_64 = 4;
    case A256GCM = 3;
    case A192GCM = 2;
    case A128GCM = 1;
    case A128KW = -3;
    case A192KW = -4;
    case A256KW = -5;
    case DIRECT = -6;
    case ES256 = -7;
    case EdDSA = -8;
    case ED256 = -260;
    case ED512 = -261;
    case DIRECT_HKDF_SHA_256 = -10;
    case DIRECT_HKDF_SHA_512 = -11;
    case DIRECT_HKDF_AES_128 = -12;
    case DIRECT_HKDF_AES_256 = -13;
    case ECDH_ES_HKDF_256 = -25;
    case ECDH_ES_HKDF_512 = -26;
    case ECDH_SS_HKDF_256 = -27;
    case ECDH_SS_HKDF_512 = -28;
    case ECDH_ES_A128KW = -29;
    case ECDH_ES_A192KW = -30;
    case ECDH_ES_A256KW = -31;
    case ECDH_SS_A128KW = -32;
    case ECDH_SS_A192KW = -33;
    case ECDH_SS_A256KW = -34;
    case ES384 = -35;
    case ES512 = -36;
    case PS256 = -37;
    case PS384 = -38;
    case PS512 = -39;
    case RSAES_OAEP = -40;
    case RSAES_OAEP_256 = -41;
    case RSAES_OAEP_512 = -42;
    case ES256K = -46;
    case RS256 = -257;
    case RS384 = -258;
    case RS512 = -259;
    case RS1 = -65535;
}
