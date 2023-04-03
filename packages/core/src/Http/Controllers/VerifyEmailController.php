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
     * @return mixed
     */
    abstract protected function sendEmailVerificationSentResponse(Request $request);

    /**
     * Sends a response indicating that the email has already been verified.
     *
     * @return mixed
     */
    abstract protected function sendEmailAlreadyVerifiedResponse(Request $request);

    /**
     * Sends a response indicating that the email has been successfully verified.
     *
     * @return mixed
     */
    abstract protected function sendEmailSuccessfullyVerifiedResponse(Request $request);

    /**
     * Handle an incoming request to (re)send the verification email.
     *
     * @see static::sendEmailAlreadyVerifiedResponse()
     * @see static::sendEmailVerificationSentResponse()
     *
     * @return mixed
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
     * @see static::sendEmailAlreadyVerifiedResponse()
     * @see static::sendEmailSuccessfullyVerifiedResponse()
     *
     * @return mixed
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
     */
    protected function hasVerifiedEmail(Request $request): bool
    {
        return $request->user()->hasVerifiedEmail();
    }

    /**
     * Send the email verification notification.
     */
    protected function sendEmailVerificationNotification(Request $request): void
    {
        $request->user()->sendEmailVerificationNotification();
    }

    /**
     * Mark the user's email as verified.
     */
    protected function markEmailAsVerified(Request $request): bool
    {
        return $request->user()->markEmailAsVerified();
    }

    /**
     * Emits an event that the user has been verified.
     */
    protected function emitsVerifiedEvent(Request $request): void
    {
        Event::dispatch(new Verified($request->user()));
    }
}
