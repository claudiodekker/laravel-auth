<?php

namespace ClaudioDekker\LaravelAuth\Database\Factories;

use App\Models\User;
use ClaudioDekker\LaravelAuth\CredentialType;
use ClaudioDekker\LaravelAuth\LaravelAuth;
use ClaudioDekker\LaravelAuth\MultiFactorCredential;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;

class MultiFactorCredentialFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = MultiFactorCredential::class;

    /**
     * Define the model's default state.
     *
     * @return array
     */
    public function definition()
    {

        return [
            'id' => fn () => 'unknown-'.Str::orderedUuid(),
            'name' => $this->faker->ean13(),
            'type' => fn () => Arr::random([CredentialType::TOTP, CredentialType::PUBLIC_KEY]),
            'secret' => 'super-secret-value',
            'created_at' => $this->faker->dateTime(),
            'user_id' => fn () => LaravelAuth::userModel()::factory(),
        ];
    }

    /**
     * Update the Factory state to generate a token for the specified user.
     *
     * @param  User  $user
     */
    public function forUser($user): self
    {
        return $this->state(['user_id' => $user]);
    }

    /**
     * Update the Factory state to generate a time-based one-time-password credential.
     */
    public function totp(): self
    {
        return $this->state([
            'id' => fn () => CredentialType::TOTP->value.'-'.Str::orderedUuid(),
            'type' => CredentialType::TOTP,
            'secret' => function () {
                $shuffled = str_shuffle('KRUGS4ZAON2HE2LOM4QHEZLBNRWHSIDJONXCO5BAMFWGYIDUNBQXIIDJNZ2GK4TFON2GS3THFQQHI4TVON2CA3LFFY');

                return substr($shuffled, 0, 32);
            },
        ]);
    }

    /**
     * Update the Factory state to generate a public key credential.
     */
    public function publicKey(): self
    {
        return $this->state([
            'id' => fn () => CredentialType::PUBLIC_KEY->value.'-'.Str::orderedUuid(),
            'type' => CredentialType::PUBLIC_KEY,
            'secret' => '{"id":"mMihuIx9LukswxBOMjMHDf6EAONOy7qdWhaQQ7dOtViR2cVB\/MNbZxURi2cvgSvKSILb3mISe9lPNG9sYgojuY5iNinYOg6hRVxmm0VssuNG2pm1+RIuTF9DUtEJZEEK","publicKey":"pQECAyYgASFYIBw\/HArIcANWNOBOxq3hH8lrHo9a17nQDxlqwybjDpHEIlggu3QUKIbALqsGuHfJI3LTKJSNmk0YCFb5oz1hjJidRMk=","signCount":0,"userHandle":"1","transports":[]}',
        ]);
    }
}
