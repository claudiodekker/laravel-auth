<?php

namespace ClaudioDekker\LaravelAuth\Testing\Partials\Challenges\Recovery;

use App\Providers\RouteServiceProvider;
use Carbon\Carbon;
use Illuminate\Support\Facades\Password;
use Symfony\Component\HttpKernel\Exception\HttpException;

trait ViewAccountRecoveryChallengePageTests
{
    /** @test */
    public function the_account_recovery_challenge_page_can_be_viewed(): void
    {
        $user = $this->generateUser();
        $token = Password::getRepository()->create($user);

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            'email' => $user->getEmailForPasswordReset(),
        ]));

        $response->assertOk();
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_authenticated(): void
    {
        $user = $this->generateUser();

        $response = $this->actingAs($user)
            ->get(route('recover-account.challenge', ['token' => 'foo']));

        $response->assertRedirect(RouteServiceProvider::HOME);
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_provided_email_does_not_resolve_to_an_existing_user(): void
    {
        $user = $this->generateUser();
        $token = Password::getRepository()->create($user);

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            'email' => 'nonexistent-user@example.com',
        ]));

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_does_not_belong_to_the_user_that_is_being_recovered(): void
    {
        $userA = $this->generateUser(['id' => 1, 'email' => 'claudio@ubient.net']);
        $userB = $this->generateUser(['id' => 2, 'email' => 'another@example.com', $this->usernameField() => $this->anotherUsername()]);
        $token = Password::getRepository()->create($userA);

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            'email' => $userB->getEmailForPasswordReset(),
        ]));

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_does_not_exist(): void
    {
        $user = $this->generateUser();

        $response = $this->get(route('recover-account.challenge', [
            'token' => 'invalid-token',
            'email' => $user->getEmailForPasswordReset(),
        ]));

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
    }

    /** @test */
    public function the_account_recovery_challenge_page_cannot_be_viewed_when_the_recovery_token_has_expired(): void
    {
        Carbon::setTestNow('2022-01-01 00:00:00');
        $user = $this->generateUser();
        $token = Password::getRepository()->create($user);
        Carbon::setTestNow(now()->addHour()->addSecond());

        $response = $this->get(route('recover-account.challenge', [
            'token' => $token,
            'email' => $user->getEmailForPasswordReset(),
        ]));

        $response->assertForbidden();
        $this->assertInstanceOf(HttpException::class, $response->exception);
        $this->assertSame('The given email and recovery token combination are invalid.', $response->exception->getMessage());
        Carbon::setTestNow();
    }
}
