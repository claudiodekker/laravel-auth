<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers;

use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;

abstract class VerifyEmailController
{
    /**
     * Sends a response indicating that the email verification link has been resent.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendEmailVerificationSentResponse(Request $request);

    /**
     * Sends a response indicating that the email has already been verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendEmailAlreadyVerifiedResponse(Request $request);

    /**
     * Sends a response indicating that the email has been successfully verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    abstract protected function sendEmailSuccessfullyVerifiedResponse(Request $request);

    /**
     * Handle an incoming request to (re)send the verification email.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     *
     * @see static::sendEmailAlreadyVerifiedResponse()
     * @see static::sendEmailVerificationSentResponse()
     */
    public function store(Request $request)
    {
        if ($this->hasVerifiedEmail($request)) {
            return $this->sendEmailAlreadyVerifiedResponse($request);
        }

        $this->sendEmailVerificationNotification($request);

        return $this->sendEmailVerificationSentResponse($request);
    }

    /**
     * Handle an incoming request to confirm the email verification.
     *
     * @param  \Illuminate\Foundation\Auth\EmailVerificationRequest  $request
     * @return mixed
     *
     * @see static::sendEmailAlreadyVerifiedResponse()
     * @see static::sendEmailSuccessfullyVerifiedResponse()
     */
    public function update(EmailVerificationRequest $request)
    {
        if ($this->hasVerifiedEmail($request)) {
            return $this->sendEmailAlreadyVerifiedResponse($request);
        }

        if ($this->markEmailAsVerified($request)) {
            $this->emitsVerifiedEvent($request);
        }

        return $this->sendEmailSuccessfullyVerifiedResponse($request);
    }

    /**
     * Determine whether the user has verified their email address.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function hasVerifiedEmail(Request $request): bool
    {
        return $request->user()->hasVerifiedEmail();
    }

    /**
     * Send the email verification notification.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function sendEmailVerificationNotification(Request $request): void
    {
        $request->user()->sendEmailVerificationNotification();
    }

    /**
     * Mark the user's email as verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function markEmailAsVerified(Request $request): bool
    {
        return $request->user()->markEmailAsVerified();
    }

    /**
     * Emits an event that the user has been verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function emitsVerifiedEvent(Request $request): void
    {
        Event::dispatch(new Verified($request->user()));
    }
}
