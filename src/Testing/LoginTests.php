<?php

namespace ClaudioDekker\LaravelAuth\Testing;

use ClaudioDekker\LaravelAuth\Testing\Partials\SubmitPasskeyBasedAuthenticationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\SubmitPasswordBasedAuthenticationTests;
use ClaudioDekker\LaravelAuth\Testing\Partials\ViewLoginPageTests;

trait LoginTests
{
    use ViewLoginPageTests;
    use SubmitPasskeyBasedAuthenticationTests;
    use SubmitPasswordBasedAuthenticationTests;
}
