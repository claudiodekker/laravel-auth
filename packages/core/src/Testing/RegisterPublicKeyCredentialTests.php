<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\PublicKey\ConfirmPublicKeyCredentialRegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\PublicKey\InitializePublicKeyCredentialRegistrationTests;

trait RegisterPublicKeyCredentialTests
{
    use InitializePublicKeyCredentialRegistrationTests;
    use ConfirmPublicKeyCredentialRegistrationTests;
}
