<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery\SubmitRecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery\ViewRecoveryChallengePageTests;

trait RecoveryChallengeTests
{
    use ViewRecoveryChallengePageTests;
    use SubmitRecoveryChallengeTests;
}
