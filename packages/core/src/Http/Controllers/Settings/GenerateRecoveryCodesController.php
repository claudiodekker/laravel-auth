<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Settings;

use ClaudioDekker\LaravelAuth\Events\RecoveryCodesGenerated;
use ClaudioDekker\LaravelAuth\RecoveryCodeManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;

abstract class GenerateRecoveryCodesController
{
    /**
     * Sends a response indicating that new recovery codes have been prepared.
     *
     * @param  \ClaudioDekker\LaravelAuth\RecoveryCodeManager  $codes
     * @return mixed
     */
    abstract protected function sendRecoveryCodesPreparedResponse(Request $request, $codes);

    /**
     * Sends a response that displays the recovery code confirmation page.
     *
     * @return mixed
     */
    abstract protected function sendConfirmationPageResponse(Request $request);

    /**
     * Sends a response indicating that the new recovery codes have been configured.
     *
     * @return mixed
     */
    abstract protected function sendRecoveryCodesConfiguredResponse(Request $request);

    /**
     * Sends a response indicating that the recovery codes configuration state is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidConfigurationStateResponse(Request $request);

    /**
     * Prepare the configuration of fresh recovery codes.
     *
     * @return mixed
     */
    public function create(Request $request)
    {
        $this->setPendingRecoveryCodes($request, $codes = $this->generateRecoveryCodes());

        return $this->sendRecoveryCodesPreparedResponse($request, $codes);
    }

    /**
     * Sends a response indicating that the provided confirmation code is invalid.
     *
     * @return mixed
     */
    abstract protected function sendInvalidRecoveryCodeResponse(Request $request);

    /**
     * Display the view for confirming that the user has saved their recovery codes.
     *
     * @return mixed
     */
    public function confirm(Request $request)
    {
        if (! $this->getPendingRecoveryCodes($request)) {
            return $this->sendInvalidConfigurationStateResponse($request);
        }

        return $this->sendConfirmationPageResponse($request);
    }

    /**
     * Confirm and finalize the generation of the recovery codes.
     *
     * @return mixed
     */
    public function store(Request $request)
    {
        $this->validateConfirmationRequest($request);

        if (! $codes = $this->getPendingRecoveryCodes($request)) {
            return $this->sendInvalidConfigurationStateResponse($request);
        }

        if (! $this->hasValidRecoveryCode($request, $codes)) {
            return $this->sendInvalidRecoveryCodeResponse($request);
        }

        $this->saveRecoveryCodes($request, $codes);
        $this->clearPendingRecoveryCodes($request);
        $this->emitRecoveryCodesGeneratedEvent($request);

        return $this->sendRecoveryCodesConfiguredResponse($request);
    }

    /**
     * Validate the recovery code confirmation request.
     *
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    protected function validateConfirmationRequest(Request $request): void
    {
        $request->validate([
            'code' => 'required|string',
        ]);
    }

    /**
     * Generates a new set of recovery codes.
     *
     * @return \ClaudioDekker\LaravelAuth\RecoveryCodeManager
     */
    protected function generateRecoveryCodes()
    {
        return RecoveryCodeManager::generate();
    }

    /**
     * Store the pending recovery codes.
     *
     * @param  \ClaudioDekker\LaravelAuth\RecoveryCodeManager  $codes
     */
    protected function setPendingRecoveryCodes(Request $request, $codes): void
    {
        $request->session()->put('auth.mfa_setup.pending_recovery_codes', $codes);
    }

    /**
     * Retrieve the pending recovery codes.
     *
     * @return \ClaudioDekker\LaravelAuth\RecoveryCodeManager|null
     */
    protected function getPendingRecoveryCodes(Request $request)
    {
        return $request->session()->get('auth.mfa_setup.pending_recovery_codes');
    }

    /**
     * Clear the pending recovery codes.
     */
    protected function clearPendingRecoveryCodes(Request $request): void
    {
        $request->session()->forget('auth.mfa_setup.pending_recovery_codes');
    }

    /**
     * Determine whether the user has entered a valid confirmation code.
     *
     * @param  \ClaudioDekker\LaravelAuth\RecoveryCodeManager  $codes
     */
    protected function hasValidRecoveryCode(Request $request, $codes): bool
    {
        return $codes->contains($request->input('code'));
    }

    /**
     * Configure the generated recovery codes.
     *
     * @param  \ClaudioDekker\LaravelAuth\RecoveryCodeManager  $codes
     */
    protected function saveRecoveryCodes(Request $request, $codes): void
    {
        $user = $request->user();

        $user->recovery_codes = $codes->toArray();
        $user->save();
    }

    /**
     * Emits an event indicating that the user has generated new recovery codes.
     */
    protected function emitRecoveryCodesGeneratedEvent(Request $request): void
    {
        Event::dispatch(new RecoveryCodesGenerated($request, Auth::user()));
    }
}
