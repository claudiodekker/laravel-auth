<?php

namespace ClaudioDekker\LaravelAuth;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

class RecoveryCodeManager implements Arrayable
{
    /**
     * The recovery codes that are being managed.
     */
    protected Collection $codes;

    /**
     * Create a new recovery code manager instance.
     *
     * @see RecoveryCodeManager::generate()
     * @see RecoveryCodeManager::from()
     */
    protected function __construct(array $codes)
    {
        $this->codes = Collection::make($codes);
    }

    /**
     * Create a new recovery code manager instance from existing codes.
     */
    public static function from(array $codes): static
    {
        return new static($codes);
    }

    /**
     * Generate a fresh batch of recovery codes.
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
     */
    protected function isIdentical(string $expected, string $provided): bool
    {
        return strtoupper(Str::remove('-', $expected)) === strtoupper(Str::remove('-', $provided));
    }

    /**
     * Determine whether the provided code exists in the collection.
     */
    public function contains(string $code): bool
    {
        return $this->codes->contains(fn ($entry) => $this->isIdentical($code, $entry));
    }

    /**
     * Remove the provided code from the collection.
     *
     * @return $this
     */
    public function remove(string $code): self
    {
        $this->codes = $this->codes->filter(fn ($entry) => ! $this->isIdentical($code, $entry));

        return $this;
    }

    /**
     * Get the recovery codes as an array.
     */
    public function toArray(): array
    {
        return $this->codes->values()->toArray();
    }
}
