<?php

namespace ClaudioDekker\LaravelAuth\Http\Controllers\Settings;

use ClaudioDekker\LaravelAuth\LaravelAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;

abstract class CredentialsController
{
    /**
     * Sends a response that displays the credential overview page.
     *
     * @return mixed
     */
    abstract protected function sendOverviewPageResponse(Request $request, Collection $mfaCredentials);

    /**
     * Sends a response indicating that the multi-factor credential could not be found.
     *
     * @param  string  $id
     * @return mixed
     */
    abstract protected function sendCredentialNotFoundResponse(Request $request, mixed $id);

    /**
     * Sends a response indicating that the multi-factor credential was deleted.
     *
     * @param  \ClaudioDekker\LaravelAuth\MultiFactorCredential  $credential
     * @return mixed
     */
    abstract protected function sendCredentialDeletedResponse(Request $request, $credential);

    /**
     * Handle an incoming request to view the credential overview page.
     *
     * @see static::sendOverviewPageResponse()
     *
     * @return mixed
     */
    public function index(Request $request)
    {
        $mfaCredentials = $this->getMultiFactorCredentials();

        return $this->sendOverviewPageResponse($request, $mfaCredentials);
    }

    /**
     * Delete a multi-factor credential.
     *
     * @see static::sendCredentialNotFoundResponse()
     * @see static::sendCredentialDeletedResponse()
     *
     * @param  string  $id
     * @return mixed
     */
    public function destroy(Request $request, mixed $id)
    {
        if (! $credential = $this->findMultiFactorCredential($id)) {
            return $this->sendCredentialNotFoundResponse($request, $id);
        }

        $this->deleteMultiFactorCredential($credential);

        return $this->sendCredentialDeletedResponse($request, $credential);
    }

    /**
     * Retrieve all multi-factor credentials for the given user.
     */
    protected function getMultiFactorCredentials(): Collection
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', Auth::id())
            ->get();
    }

    /**
     * Retrieve a multi-factor credential by it's ID for the current user.
     *
     * @param  string  $id
     * @return \ClaudioDekker\LaravelAuth\MultiFactorCredential|null
     */
    protected function findMultiFactorCredential(mixed $id)
    {
        return LaravelAuth::multiFactorCredential()->query()
            ->where('user_id', Auth::id())
            ->find($id);
    }

    /**
     * Delete the given multi-factor credential.
     *
     * @param  \ClaudioDekker\LaravelAuth\MultiFactorCredential  $credential
     */
    protected function deleteMultiFactorCredential($credential): void
    {
        LaravelAuth::multiFactorCredential()->query()
            ->where('id', $credential->id)
            ->delete();
    }
}
