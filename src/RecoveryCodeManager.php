<?php

namespace ClaudioDekker\LaravelAuth;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class RecoveryCodeManager implements Arrayable
{
    /**
     * The recovery codes that are being managed.
     *
     * @var \Illuminate\Support\Collection
     */
    protected Collection $codes;

    /**
     * Create a new recovery code manager instance.
     *
     * @see RecoveryCodeManager::generate()
     * @see RecoveryCodeManager::from()
     *
     * @param  array  $codes
     */
    protected function __construct(array $codes)
    {
        $this->codes = Collection::make($codes);
    }

    /**
     * Create a new recovery code manager instance from existing codes.
     *
     * @param  array  $codes
     * @return static
     */
    public static function from(array $codes): static
    {
        return new static($codes);
    }

    /**
     * Generate a fresh batch of recovery codes.
     *
     * @return static
     */
    public static function generate(): static
    {
        return new static(Collection::times(8, static fn () => Str::random(10))
            ->map(fn ($code) => strtoupper($code))
            ->map(fn ($code) => chunk_split($code, 5, '-'))
            ->map(fn ($code) => substr($code, 0, -1))
            ->toArray()
        );
    }

    /**
     * Determine whether the provided codes are identical.
     *
     * @param  string  $expected
     * @param  string  $provided
     * @return bool
     */
    protected function isIdentical(string $expected, string $provided): bool
    {
        return strtoupper(Str::remove('-', $expected)) === strtoupper(Str::remove('-', $provided));
    }

    /**
     * Determine whether the provided code exists in the collection.
     *
     * @param  string  $code
     * @return bool
     */
    public function contains(string $code): bool
    {
        return $this->codes->contains(fn ($entry) => $this->isIdentical($code, $entry));
    }

    /**
     * Remove the provided code from the collection.
     *
     * @param  string  $code
     * @return $this
     */
    public function remove(string $code): self
    {
        $this->codes = $this->codes->filter(fn ($entry) => ! $this->isIdentical($code, $entry));

        return $this;
    }

    /**
     * Get the recovery codes as an array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return $this->codes->values()->toArray();
    }
}
