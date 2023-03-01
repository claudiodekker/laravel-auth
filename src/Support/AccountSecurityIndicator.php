<?php

namespace ClaudioDekker\LaravelAuth\Support;

use Illuminate\Contracts\Support\Arrayable;

enum AccountSecurityIndicator implements Arrayable
{
    case NO_MFA_NO_RECOVERY_CODES;
    case NO_MFA_HAS_RECOVERY_CODES;
    case HAS_MFA_NO_RECOVERY_CODES;
    case HAS_MFA_HAS_RECOVERY_CODES;

    /**
     * Determine the color of the indicator.
     */
    public function color(): string
    {
        return match ($this) {
            self::NO_MFA_NO_RECOVERY_CODES, self::NO_MFA_HAS_RECOVERY_CODES => 'RED',
            self::HAS_MFA_NO_RECOVERY_CODES => 'ORANGE',
            self::HAS_MFA_HAS_RECOVERY_CODES => 'GREEN',
        };
    }

    /**
     * Determine whether the account security indicator has any issues to indicate.
     */
    public function hasIssues(): bool
    {
        return $this->color() !== 'GREEN';
    }

    /**
     * Determine the message that should be displayed for the indicator.
     */
    public function message(): string
    {
        return match ($this) {
            self::NO_MFA_NO_RECOVERY_CODES => __('laravel-auth::auth.security-indicator.no-mfa-no-recovery-codes'),
            self::NO_MFA_HAS_RECOVERY_CODES => __('laravel-auth::auth.security-indicator.no-mfa-has-recovery-codes'),
            self::HAS_MFA_NO_RECOVERY_CODES => __('laravel-auth::auth.security-indicator.has-mfa-no-recovery-codes'),
            self::HAS_MFA_HAS_RECOVERY_CODES => __('laravel-auth::auth.security-indicator.has-mfa-has-recovery-codes'),
        };
    }

    /**
     * Get the instance as an array.
     *
     * @return array<TKey, TValue>
     */
    public function toArray()
    {
        return [
            'color' => $this->color(),
            'has_issues' => $this->hasIssues(),
            'message' => $this->message(),
        ];
    }
}
