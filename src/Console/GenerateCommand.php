<?php

namespace ClaudioDekker\LaravelAuth\Console;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Str;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;

abstract class GenerateCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'auth:generate {--y|yes} {--t|without-rate-limiting} {--e|register-without-email-verification} {--b|without-views} {--k|kind=}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate authentication scaffolding for your application.';

    /**
     * The filesystem instance.
     *
     * @var Filesystem
     */
    protected $files;

    /**
     * The determined authentication generation options.
     *
     * @var bool[]
     */
    protected $determinedOptions = [];

    /**
     * Determines the path to the extending package.
     *
     * @return string
     */
    abstract protected function determinePackagePath(): string;

    /**
     * Create a new console command instance.
     *
     * @return void
     */
    public function __construct(Filesystem $files)
    {
        parent::__construct();

        $this->files = $files;
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle(): void
    {
        View::addExtension('bladetmpl', 'blade');
        View::addNamespace('laravel-auth-core-templates', $this->determineCorePackageInstallationPath().'/templates');
        View::addNamespace('laravel-auth-package-templates', $this->determinePackagePath().'/templates');

        $flavors = ['email-based', 'username-based'];

        $this->determinedOptions = [
            'withoutRateLimiting' => $this->option('without-rate-limiting') || ! ($this->option('yes') || $this->confirm('Do you want authentication attempts to be rate-limited? (Strongly recommended)', true)),
            'withoutEmailVerification' => $this->option('register-without-email-verification') || ! ($this->option('yes') || $this->confirm('Do you want to send a verification email when users register?', true)),
            'withoutViews' => $this->option('without-views'),
            'flavor' => $this->option('kind') && in_array($this->option('kind'), $flavors, true) ? $this->option('kind') : ($this->option('yes') ? 'email-based' : $this->choice('What flavor of user accounts do you want to use?', $flavors, 0)),
        ];

        $this->install();
    }

    /**
     * Install the authentication scaffolding into the application.
     *
     * @return void
     */
    protected function install(): void
    {
        $this->installRoutes();
        $this->installScheduledTasks();
        $this->installControllers();
        $this->installTests();

        if (! $this->determinedOptions['withoutViews']) {
            $this->installViews();
        }

        $this->installCoreOverrides();
    }

    /**
     * Installs the extending package's authentication routes.
     *
     * @return void
     */
    abstract protected function installRoutes(): void;

    /**
     * Installs the extending package's authentication tests.
     *
     * @return void
     */
    abstract protected function installTests(): void;

    /**
     * Updates the scheduler to run authentication-related tasks.
     *
     * @return void
     */
    protected function installScheduledTasks(): void
    {
        $this->rawGenerate('Console.Kernel', app_path('Console/Kernel.php'));
        $this->rawGenerate('Tests.PruneUnclaimedUsersTest', base_path('tests/Unit/PruneUnclaimedUsersTest.php'));
    }

    /**
     * Installs the extending package's authentication controllers.
     *
     * @return void
     */
    protected function installControllers(): void
    {
        $this->generate('Controllers.AccountRecoveryRequestController', app_path('Http/Controllers/Auth/AccountRecoveryRequestController.php'));
        $this->generate('Controllers.Challenges.AccountRecoveryChallengeController', app_path('Http/Controllers/Auth/Challenges/AccountRecoveryChallengeController.php'));
        $this->generate('Controllers.Challenges.MultiFactorChallengeController', app_path('Http/Controllers/Auth/Challenges/MultiFactorChallengeController.php'));
        $this->generate('Controllers.Challenges.SudoModeChallengeController', app_path('Http/Controllers/Auth/Challenges/SudoModeChallengeController.php'));
        $this->generate('Controllers.LoginController', app_path('Http/Controllers/Auth/LoginController.php'));
        $this->generate('Controllers.RegisterController', app_path('Http/Controllers/Auth/RegisterController.php'));
        $this->generate('Controllers.VerifyEmailController', app_path('Http/Controllers/Auth/VerifyEmailController.php'));
        $this->generate('Controllers.Settings.ChangePasswordController', app_path('Http/Controllers/Auth/Settings/ChangePasswordController.php'));
        $this->generate('Controllers.Settings.CredentialsController', app_path('Http/Controllers/Auth/Settings/CredentialsController.php'));
        $this->generate('Controllers.Settings.GenerateRecoveryCodesController', app_path('Http/Controllers/Auth/Settings/GenerateRecoveryCodesController.php'));
        $this->generate('Controllers.Settings.RegisterPublicKeyCredentialController', app_path('Http/Controllers/Auth/Settings/RegisterPublicKeyCredentialController.php'));
        $this->generate('Controllers.Settings.RegisterTotpCredentialController', app_path('Http/Controllers/Auth/Settings/RegisterTotpCredentialController.php'));
    }

    /**
     * Installs the extending package's authentication views.
     *
     * @return void
     */
    abstract protected function installViews(): void;

    /**
     * Overrides some of the files in Laravel's application scaffolding with the core package's own versions.
     *
     * @return void
     */
    protected function installCoreOverrides(): void
    {
        $this->rawGenerate('Database.User', app_path('Models/User.php'));
        $this->rawGenerate('Database.UserFactory', database_path('factories/UserFactory.php'));
        $this->rawGenerate('Database.2014_10_12_000000_create_users_table', database_path('migrations/2014_10_12_000000_create_users_table.php'));
    }

    /**
     * Renders a (Blade) Template from the extending package and writes it to an application path.
     *
     * @see static::determinePackagePath()
     *
     * @param  string  $template
     * @param  string  $path
     * @return bool
     */
    protected function generate(string $template, string $path): bool
    {
        return $this->rawGenerate($template, $path, 'laravel-auth-package-templates');
    }

    /**
     * Copies a stub file from the extending package and writes it to the given application path.
     *
     * @see static::determinePackagePath()
     *
     * @param  string  $stub
     * @param  string  $path
     * @return bool
     */
    protected function copy(string $stub, string $path): bool
    {
        $contents = file_exists($this->determinePackagePath().'/stubs/'.$this->determinedOptions['flavor'].'/'.$stub)
            ? file_get_contents($this->determinePackagePath().'/stubs/'.$this->determinedOptions['flavor'].'/'.$stub)
            : file_get_contents($this->determinePackagePath().'/stubs/defaults/'.$stub);

        if ($contents && $this->writeContentsToFile($contents, $path)) {
            $this->info("Stub [$stub] successfully copied to [$path].");

            return true;
        }

        $this->error("Failed to copy stub [$stub] to [$path].");

        return false;
    }

    /**
     * Renders a (Blade) Template and writes it to an application path.
     *
     * @see static::generate()
     *
     * @param  string  $template
     * @param  string  $path
     * @param  string  $namespace
     * @return bool
     */
    protected function rawGenerate(string $template, string $path, string $namespace = 'laravel-auth-core-templates'): bool
    {
        $contents = "<?php\n\n".View::make($namespace.'::'.$template, $this->determinedOptions)->render();

        if ($this->writeContentsToFile($contents, $path)) {
            $this->info("File successfully generated at [$path].");

            return true;
        }

        $this->error("Failed to store generated file at [$path].");

        return false;
    }

    /**
     * Execute the given command within the project's root directory.
     *
     * @param  string  $command
     * @param  int  $expectedExitCode
     * @return bool
     */
    protected function exec(string $command, int $expectedExitCode = 0): bool
    {
        $arguments = explode(' ', $command);

        if (isset($arguments[0]) && $arguments[0] === 'php') {
            $arguments[0] = (new PhpExecutableFinder())->find(false) ?: 'php';
        }

        $this->comment('Executing command: '.implode(' ', $arguments));
        $this->comment(Str::repeat('-', 80));

        $exitCode = (new Process($arguments, base_path()))
            ->setTimeout(600)
            ->run(fn ($type, $output) => $this->output->write($output));

        if ($exitCode !== $expectedExitCode) {
            $this->error("Command exited with unexpected code [$exitCode].");

            return false;
        }

        $this->comment(Str::repeat('-', 37).' DONE '.Str::repeat('-', 37));

        return true;
    }

    /**
     * Writes the given contents to the given file path.
     *
     * @param  string  $contents
     * @param  string  $path
     * @return bool
     */
    private function writeContentsToFile(string $contents, string $path): bool
    {
        if (! $this->files->isDirectory(dirname($path))) {
            $this->files->makeDirectory(dirname($path), 0777, true, true);
        }

        return $this->files->put($path, $contents) !== false;
    }

    /**
     * Determine the path at which the package is located.
     *
     * @return string
     */
    protected function determineCorePackageInstallationPath(): string
    {
        return dirname(__FILE__, 3);
    }
}
