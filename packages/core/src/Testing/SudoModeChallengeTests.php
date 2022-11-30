<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode\ConfirmSudoModeUsingCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode\ConfirmSudoModeUsingPasswordTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\SudoMode\ViewSudoModeChallengePageTests;

trait SudoModeChallengeTests
{
    use ViewSudoModeChallengePageTests;
    use ConfirmSudoModeUsingPasswordTests;
    use ConfirmSudoModeUsingCredentialTests;
}
