<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\SubmitRecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\ViewRecoveryRequestPageTests;

trait RecoveryRequestTests
{
    use ViewRecoveryRequestPageTests;
    use SubmitRecoveryRequestTests;
}
