<?php

namespace ClaudioDekker\LaravelAuth\Http\Traits;

use Illuminate\Contracts\Auth\Authenticatable;

trait WithoutVerificationEmail
{
    /**
     * Send the email verification notification.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function sendEmailVerificationNotification(Authenticatable $user): void
    {
        //
    }
}
