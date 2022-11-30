<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor\SubmitMultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\MultiFactor\ViewMultiFactorChallengePageTests;

trait MultiFactorChallengeTests
{
    use ViewMultiFactorChallengePageTests;
    use SubmitMultiFactorChallengeTests;
}
