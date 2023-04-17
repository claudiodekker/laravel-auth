<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\Factories\UserFactory;

class MultiFactorCredentialTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_belongs_to_an_user(): void
    {
        $user = UserFactory::new()->create();

        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->create([
            'user_id' => $user->id,
        ]);

        $this->assertInstanceOf(LaravelAuth::userModel(), $credential->user);
        $this->assertTrue($credential->user->is($user));
    }

    /** @test */
    public function it_can_customize_the_user_relationship_model_based_on_the_standard_laravel_auth_config(): void
    {
        config([
            'auth.defaults.guard' => 'foo',
            'auth.guards.foo.provider' => 'bar',
            'auth.providers.bar.model' => LaravelAuth::userModel(),
        ]);
        $user = UserFactory::new()->create();

        $credential = LaravelAuth::multiFactorCredentialModel()::factory()->create([
            'user_id' => $user->id,
        ]);

        $this->assertInstanceOf(LaravelAuth::userModel(), $credential->user);
        $this->assertTrue($credential->user->is($user));
    }

    /** @test */
    public function it_does_not_expose_the_secret_when_serialized(): void
    {
        $token = LaravelAuth::multiFactorCredentialModel()::factory()->create([
            'user_id' => 1,
            'secret' => 'foo',
        ]);

        $this->assertArrayNotHasKey('secret', $token->toArray());
    }
}
