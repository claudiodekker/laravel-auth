<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery\ConfirmRecoveryCodesGenerationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery\InitializeRecoveryCodesGenerationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Settings\Recovery\ViewRecoveryCodesGenerationConfirmationPageTests;

trait GenerateRecoveryCodesTests
{
    use InitializeRecoveryCodesGenerationTests;
    use ViewRecoveryCodesGenerationConfirmationPageTests;
    use ConfirmRecoveryCodesGenerationTests;
}
