<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp\CancelTotpCredentialRegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp\ConfirmTotpCredentialRegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp\InitializeTotpCredentialRegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Totp\ViewTotpCredentialRegistrationConfirmationPageTests;

trait RegisterTotpCredentialTests
{
    use InitializeTotpCredentialRegistrationTests;
    use ViewTotpCredentialRegistrationConfirmationPageTests;
    use ConfirmTotpCredentialRegistrationTests;
    use CancelTotpCredentialRegistrationTests;
}
