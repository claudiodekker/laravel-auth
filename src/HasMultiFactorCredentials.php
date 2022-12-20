<?php

namespace ClaudioDekker\LaravelAuth;

trait HasMultiFactorCredentials
{
    /**
     * Get all of the multi factor credentials for the user.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function multiFactorCredentials()
    {
        return $this->hasMany(LaravelAuth::multiFactorCredentialModel(), 'user_id')->orderBy('created_at', 'desc');
    }
}
