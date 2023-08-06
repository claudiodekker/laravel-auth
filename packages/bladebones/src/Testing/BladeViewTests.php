<?php

namespace ClaudioDekker\LaravelAuthBladebones\Testing;

use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\CredentialsOverviewViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\LoginViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\MultiFactorChallengeViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\RecoveryChallengeViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\RecoveryRequestViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\RegisterPublicKeyCredentialViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\RegisterTotpCredentialViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\RegisterViewTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\Partials\SudoModeChallengeViewTests;

trait BladeViewTests
{
    use RegisterViewTests;
    use LoginViewTests;
    use RecoveryRequestViewTests;

    // Challenges
    use MultiFactorChallengeViewTests;
    use RecoveryChallengeViewTests;
    use SudoModeChallengeViewTests;

    // Settings
    use CredentialsOverviewViewTests;
    use RegisterPublicKeyCredentialViewTests;
    use RegisterTotpCredentialViewTests;
}
