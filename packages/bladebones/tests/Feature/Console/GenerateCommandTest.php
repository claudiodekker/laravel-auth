<?php

namespace ClaudioDekker\LaravelAuthBladebones\Tests\Feature\Console;

use ClaudioDekker\LaravelAuthBladebones\Console\GenerateCommand;
use ClaudioDekker\LaravelAuthBladebones\Tests\TestCase;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Mockery;

class GenerateCommandTest extends TestCase
{
    /**
     * @var GenerateCommand;
     */
    protected $command;

    /**
     * @var Mockery\LegacyMockInterface|Mockery\MockInterface
     */
    protected $mock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mock = Mockery::mock(Filesystem::class);
        $this->app->instance(Filesystem::class, $this->mock);
    }

    /** @test */
    public function it_creates_a_directory_when_it_does_not_exist(): void
    {
        $this->mock->shouldReceive('isDirectory')->atLeast()->once()->withArgs([app_path('Http/Controllers/Auth')])->andReturn(false, true);
        $this->mock->shouldReceive('makeDirectory')->once()->withSomeOfArgs(app_path('Http/Controllers/Auth'))->andReturn(true);
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--yes' => true]);
    }

    /** @test */
    public function it_does_not_create_the_directory_when_it_already_exists(): void
    {
        $this->mock->shouldReceive('isDirectory')->atLeast()->once()->withArgs([app_path('Http/Controllers/Auth')])->andReturn(true);
        $this->mock->shouldNotReceive('makeDirectory')->withSomeOfArgs(app_path('Http/Controllers/Auth'));
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--yes' => true]);
    }

    /** @test */
    public function it_accepts_all_default_options_without_prompting_when_passing_the_yes_flag(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController');
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringNotContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringNotContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\EmailBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\BladeViewTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use BladeViewTests;
    use EmailBased;
    use RegisterWithVerificationEmailTests;

    // Basic Auth
    use RegistrationTests;
    use RecoveryRequestTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });
        $this->assertMockShouldReceiveView('auth/challenges/multi_factor');
        $this->assertMockShouldReceiveView('auth/challenges/recovery');
        $this->assertMockShouldReceiveView('auth/challenges/sudo_mode');
        $this->assertMockShouldReceiveView('auth/login');
        $this->assertMockShouldReceiveView('auth/recover-account');
        $this->assertMockShouldReceiveView('auth/register');
        $this->assertMockShouldReceiveView('auth/settings/confirm_public_key');
        $this->assertMockShouldReceiveView('auth/settings/confirm_recovery_codes');
        $this->assertMockShouldReceiveView('auth/settings/confirm_totp');
        $this->assertMockShouldReceiveView('auth/settings/credentials');
        $this->assertMockShouldReceiveView('auth/settings/recovery_codes');
        $this->assertMockShouldReceiveView('home');
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--yes' => true]);
    }

    /** @test */
    public function it_asks_whether_you_want_to_send_verification_emails_on_registration(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController');
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringNotContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringNotContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\EmailBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use EmailBased;
    use RegisterWithVerificationEmailTests;

    // Basic Auth
    use RecoveryRequestTests;
    use RegistrationTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use RecoveryChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });

        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--without-views' => true, '--kind' => 'email-based'])
            ->expectsConfirmation('Do you want to send a verification email when users register?', 'yes');
    }

    /** @test */
    public function it_does_not_send_verification_emails_on_registration_when_you_answer_the_email_verification_question_with_no(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController');
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithoutVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\EmailBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use EmailBased;
    use RegisterWithoutVerificationEmailTests;

    // Basic Auth
    use RecoveryRequestTests;
    use RegistrationTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use RecoveryChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--without-views' => true,  '--kind' => 'email-based'])
            ->expectsConfirmation('Do you want to send a verification email when users register?', 'no');
    }

    /** @test */
    public function it_does_not_send_verification_emails_on_registration_when_the_register_without_email_verification_flag_was_passed(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController');
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithoutVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\EmailBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use ClaudioDekker\LaravelAuthBladebones\Testing\BladeViewTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use BladeViewTests;
    use EmailBased;
    use RegisterWithoutVerificationEmailTests;

    // Basic Auth
    use RecoveryRequestTests;
    use RegistrationTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use RecoveryChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--yes' => true, '--register-without-email-verification' => true]);
    }

    /** @test */
    public function it_does_not_create_views_and_view_tests_when_the_without_views_flag_was_passed(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController');
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringNotContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringNotContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\EmailBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use EmailBased;
    use RegisterWithVerificationEmailTests;

    // Basic Auth
    use RecoveryRequestTests;
    use RegistrationTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use RecoveryChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });
        $this->assertMockShouldNotReceiveView('auth/challenges/multi_factor');
        $this->assertMockShouldNotReceiveView('auth/challenges/recovery');
        $this->assertMockShouldNotReceiveView('auth/challenges/sudo_mode');
        $this->assertMockShouldNotReceiveView('auth/login');
        $this->assertMockShouldNotReceiveView('auth/recover-account');
        $this->assertMockShouldNotReceiveView('auth/register');
        $this->assertMockShouldNotReceiveView('auth/settings/confirm_public_key');
        $this->assertMockShouldNotReceiveView('auth/settings/confirm_recovery_codes');
        $this->assertMockShouldNotReceiveView('auth/settings/confirm_totp');
        $this->assertMockShouldNotReceiveView('auth/settings/credentials');
        $this->assertMockShouldNotReceiveView('auth/settings/recovery_codes');
        $this->assertMockShouldNotReceiveView('home');
        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--yes' => true, '--without-views' => true]);
    }

    /** @test */
    public function it_asks_what_flavor_of_user_accounts_should_be_used(): void
    {
        $this->assertMockShouldReceiveController('Settings/ChangePasswordController');
        $this->assertMockShouldReceiveController('Settings/CredentialsController');
        $this->assertMockShouldReceiveController('Settings/RegisterPublicKeyCredentialController');
        $this->assertMockShouldReceiveController('Settings/RegisterTotpCredentialController');
        $this->assertMockShouldReceiveController('VerifyEmailController');
        $this->assertMockShouldReceiveController('RecoveryRequestController');
        $this->assertMockShouldReceiveController('Challenges/RecoveryChallengeController');
        $this->assertMockShouldReceiveController('Challenges/MultiFactorChallengeController');
        $this->assertMockShouldReceiveController('Challenges/SudoModeChallengeController');
        $this->assertMockShouldReceiveController('LoginController', function ($contents) {
            $this->assertStringContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\UsernameBased;\n", $contents);
            $this->assertStringContainsString("use UsernameBased;\n", $contents);
        });
        $this->assertMockShouldReceiveController('RegisterController', function ($contents) {
            $this->assertStringContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\UsernameBased;\n", $contents);
            $this->assertStringContainsString("use ClaudioDekker\LaravelAuth\Http\Modifiers\WithoutVerificationEmail;\n", $contents);
            $this->assertStringContainsString("use UsernameBased;\n", $contents);
            $this->assertStringContainsString("use WithoutVerificationEmail;\n", $contents);
        });
        $this->assertMockShouldReceiveTest('Unit/PruneUnclaimedUsersTest');
        $this->assertMockShouldReceiveTest('Unit/UserTest');
        $this->assertMockShouldReceiveTest('Feature/AuthenticationTest', function ($contents) {
            $expected = <<<EOF
<?php

namespace Tests\Feature;

use ClaudioDekker\LaravelAuth\Testing\EmailVerification\RegisterWithoutVerificationEmailTests;
use ClaudioDekker\LaravelAuth\Testing\EmailVerificationTests;
use ClaudioDekker\LaravelAuth\Testing\Flavors\UsernameBased;
use ClaudioDekker\LaravelAuth\Testing\GenerateRecoveryCodesTests;
use ClaudioDekker\LaravelAuth\Testing\LoginTests;
use ClaudioDekker\LaravelAuth\Testing\LogoutTests;
use ClaudioDekker\LaravelAuth\Testing\MultiFactorChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\RecoveryRequestTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterPublicKeyCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegisterTotpCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\RegistrationTests;
use ClaudioDekker\LaravelAuth\Testing\RemoveCredentialTests;
use ClaudioDekker\LaravelAuth\Testing\SubmitChangePasswordTests;
use ClaudioDekker\LaravelAuth\Testing\SudoModeChallengeTests;
use ClaudioDekker\LaravelAuth\Testing\ViewCredentialsOverviewPageTests;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    // Configuration Mixins
    use RegisterWithoutVerificationEmailTests;
    use UsernameBased;

    // Basic Auth
    use RecoveryRequestTests;
    use RegistrationTests;
    use LoginTests;
    use LogoutTests;

    // Challenges
    use MultiFactorChallengeTests;
    use RecoveryChallengeTests;
    use SudoModeChallengeTests;

    // Settings
    use ViewCredentialsOverviewPageTests;
    use EmailVerificationTests;
    use GenerateRecoveryCodesTests;
    use SubmitChangePasswordTests;
    use RegisterPublicKeyCredentialTests;
    use RegisterTotpCredentialTests;
    use RemoveCredentialTests;

    protected function setUp(): void
    {
        parent::setUp();

        \$this->useInstantlyResolvingTimebox();
    }
}

EOF;

            $this->assertSame($contents, $expected);

            return true;
        });

        $this->mock->shouldIgnoreMissing();

        $this->artisan(GenerateCommand::class, ['--without-views' => true, '--register-without-email-verification' => true])
            ->expectsChoice('What flavor of user accounts do you want to use?', 'username-based', ['email-based', 'username-based']);
    }

    protected function assertMockShouldReceiveController(string $filename, callable $callback = null): void
    {
        $this->mock->shouldReceive('put')->once()->withArgs(function ($path, $contents) use ($filename, $callback) {
            $className = Str::afterLast($filename, '/');

            $found = $path === app_path("Http/Controllers/Auth/$filename.php")
                && str_contains($contents, "class $className extends BaseController");

            if ($found && $callback) {
                $callback($contents);
            }

            return $found;
        });
    }

    protected function assertMockShouldReceiveTest(string $filename, callable $callback = null): void
    {
        $this->mock->shouldReceive('put')->once()->withArgs(function ($path, $contents) use ($filename, $callback) {
            $className = Str::afterLast($filename, '/');

            return $path === base_path("tests/$filename.php")
                && str_contains($contents, "class $className extends TestCase")
                && (! $callback || $callback($contents));
        });
    }

    protected function assertMockShouldReceiveView(string $filename, callable $callback = null): void
    {
        $this->mock->shouldReceive('put')->once()->withArgs(function ($path, $contents) use ($filename, $callback) {
            return $path === resource_path("views/$filename.blade.php")
                && (! $callback || $callback($contents));
        });
    }

    protected function assertMockShouldNotReceiveView(string $filename, callable $callback = null): void
    {
        $this->mock->shouldReceive('put')->never()->withArgs(function ($path, $contents) use ($filename, $callback) {
            return $path === resource_path("views/$filename.blade.php")
                && (! $callback || $callback($contents));
        });
    }
}
