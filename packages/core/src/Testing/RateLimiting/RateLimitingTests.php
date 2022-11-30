<?php

namespace ClaudioDekker\LaravelAuth\Testing\RateLimiting;

use ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting\AccountRecoveryChallengeRateLimitingTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting\AccountRecoveryRequestRateLimitingTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting\LoginRateLimitingTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting\MultiFactorChallengeRateLimitingTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\RateLimiting\SudoModeRateLimitingTests;

trait RateLimitingTests
{
    use LoginRateLimitingTests;
    use AccountRecoveryRequestRateLimitingTests;
    use AccountRecoveryChallengeRateLimitingTests;
    use MultiFactorChallengeRateLimitingTests;
    use SudoModeRateLimitingTests;
}
