<?php

namespace ClaudioDekker\LaravelAuth\Console;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\View;

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
            'useStrictTypes' => version_compare(App::version(), "10.0", ">="),
        ];

        $this->install();
    }

    /**
     * Install the authentication scaffolding into the application.
     */
    protected function install(): void
    {
        $this->installRoutes();
        $this->installControllers();
        $this->installTests();

        if (! $this->determinedOptions['withoutViews']) {
            $this->installViews();
        }

        $this->installCoreOverrides();
    }

    /**
     * Installs the extending package's authentication routes.
     */
    abstract protected function installRoutes(): void;

    /**
     * Installs the extending package's authentication views.
     */
    abstract protected function installViews(): void;

    /**
     * Installs the extending package's authentication tests.
     */
    protected function installTests(): void
    {
        $this->rawGenerate('Tests.PruneUnclaimedUsersTest', base_path('tests/Unit/PruneUnclaimedUsersTest.php'));
        $this->rawGenerate('Tests.UserTest', base_path('tests/Unit/UserTest.php'));
    }

    /**
     * Installs the extending package's authentication controllers.
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
     * Overrides some of the files in Laravel's application scaffolding with the core package's own versions.
     */
    protected function installCoreOverrides(): void
    {
        $this->rawGenerate('Console.Kernel', app_path('Console/Kernel.php'));
        $this->rawGenerate('Database.User', app_path('Models/User.php'));
        $this->rawGenerate('Database.UserFactory', database_path('factories/UserFactory.php'));
        $this->rawGenerate('Database.2014_10_12_000000_create_users_table', database_path('migrations/2014_10_12_000000_create_users_table.php'));
    }

    /**
     * Renders a (Blade) Template from the extending package and writes it to an application path.
     *
     * @see static::determinePackagePath()
     */
    protected function generate(string $template, string $path): bool
    {
        return $this->rawGenerate($template, $path, 'laravel-auth-package-templates');
    }

    /**
     * Copies a stub file from the extending package and writes it to the given application path.
     *
     * @see static::determinePackagePath()
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
     * Writes the given contents to the given file path.
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
     */
    protected function determineCorePackageInstallationPath(): string
    {
        return dirname(__FILE__, 3);
    }
}
