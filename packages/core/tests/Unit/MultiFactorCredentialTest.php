<?php

namespace ClaudioDekker\LaravelAuth\Tests\Unit;

use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use ClaudioDekker\LaravelAuth\Tests\TestCase;
use Illuminate\Foundation\Auth\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\Factories\UserFactory;

class MultiFactorCredentialTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_belongs_to_an_user(): void
    {
        $user = UserFactory::new()->create();

        $credential = MultiFactorCredential::factory()->create([
            'user_id' => $user->id,
        ]);

        $this->assertInstanceOf(User::class, $credential->user);
        $this->assertTrue($credential->user->is($user));
    }

    /** @test */
    public function it_can_customize_the_user_relationship_model_based_on_the_standard_laravel_auth_config(): void
    {
        config([
            'auth.defaults.guard' => 'foo',
            'auth.guards.foo.provider' => 'bar',
            'auth.providers.bar.model' => User::class,
        ]);
        $user = UserFactory::new()->create();

        $credential = MultiFactorCredential::factory()->create([
            'user_id' => $user->id,
        ]);

        $this->assertInstanceOf(User::class, $credential->user);
        $this->assertTrue($credential->user->is($user));
    }

    /** @test */
    public function it_can_customize_the_database_connection(): void
    {
        $this->assertSame('testbench', (new MultiFactorCredential())->getConnectionName());

        config(['laravel-auth.database.connection' => null]);

        $this->assertNull((new MultiFactorCredential())->getConnectionName());
    }

    /** @test */
    public function it_does_not_expose_the_secret_when_serialized(): void
    {
        $token = MultiFactorCredential::factory()->create([
            'user_id' => 1,
            'secret' => 'foo',
        ]);

        $this->assertArrayNotHasKey('secret', $token->toArray());
    }
}
