<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\SubmitAccountRecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\ViewAccountRecoveryRequestPageTests;

trait AccountRecoveryRequestTests
{
    use ViewAccountRecoveryRequestPageTests;
    use SubmitAccountRecoveryRequestTests;
}
