/*
 *    Copyright (c) 2026 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#pragma once

#include <lib/core/CHIPCallback.h>
#include <lib/core/CHIPError.h>
#include <lib/support/DLLUtil.h>
#include <lib/support/Span.h>

namespace chip {
namespace Controller {

/**
 * Callback for NetworkIdentityRegistrar::GetNetworkIdentity()
 * @param networkIdentity The Network Identity in compact-pdc-identity TLV format.
 *                        Only valid if status is CHIP_NO_ERROR.
 */
typedef void (*OnNetworkIdentityAvailableFunct)(void * context, CHIP_ERROR status, ByteSpan networkIdentity);

/**
 * Callback for NetworkIdentityRegistrar::RegisterClient()
 */
typedef void (*OnClientRegisteredFunct)(void * context, CHIP_ERROR status);

/**
 * Callback for NetworkIdentityRegistrar::UnregisterClient()
 */
typedef void (*OnClientUnregisteredFunct)(void * context, CHIP_ERROR status);

/**
 * Grants a commissioner access to a network that uses Per-Device Credentials (PDC).
 *
 * The operations mirror the Network Identity Management cluster one-to-one; a registrar is
 * generally a client of that cluster on a Network Infrastructure Manager, but nothing here
 * requires that. Deciding *which* network to join (i.e. determining the SSID) is not part of this
 * interface; that information is supplied to the commissioner separately, alongside the
 * registrar, in WiFiCredentials.
 *
 * Asynchronous methods must either return an error and never invoke their callback, or return
 * CHIP_NO_ERROR and invoke the callback exactly once. Completing the callback synchronously, i.e.
 * before returning from the asynchronous method, is allowed.
 *
 * Callbacks are passed as Owned tokens, so a pending callback is cancellable per the usual Callback
 * contract: cancelling it makes the registrar relinquish it, and a cancelled request must never be
 * completed (e.g. it could result in a UAF if the context the callback points to was deallocated).
 *
 * The memory backing any span passed to a registrar method is only guaranteed to remain valid for
 * the duration of that call, and any span passed to a callback also need only remain valid for the
 * duration of the callback.
 *
 * Lifecycle:
 *  - A registrar instance usually serves a single DeviceCommissioner, which commissions one device
 *    at a time. It may serve any number of consecutive commissioning attempts, so an instance can
 *    live for as long as the commissioner does.
 *  - The commissioner keeps at most one GetNetworkIdentity() or RegisterClient() call, and at
 *    most one UnregisterClient() call in flight at the same time. UnregisterClient() can overlap the
 *    other calls, because a revoke issued as a commissioning attempt ends is not waited for.
 *  - Unless documented otherwise, concrete registrar implementations may be relying on these
 *    constraints on concurrent requests, and therefore will not support sharing a single registrar
 *    instance between multiple commissioners.
 *  - The registrar must remain valid as long as it is referenced by the CommissioningParameters of
 *    an in-progress commissioning attempt and/or has any active asynchronous operations for which
 *    the caller is still owed a callback.
 *
 * Note that while DeviceCommissioner::StopPairing() will synchronously abort and clean up an
 * ongoing commissioning attempt, it does generally *not* result in the registrar becoming idle
 * synchronously: If a Network Client Identity was already installed via the registrar, the
 * commissioner will issue an UnregisterClient() call to revoke it. Unless that request succeeds (or
 * fails) synchronously, it will not be complete by the time StopPairing() returns. If a registrar
 * must be released synchronously (e.g. to swap it with one pointed at a different network), the
 * recipe is to (1) stop the pairing that uses the registrar, and then (2) call a Shutdown() method
 * (which the concrete registrar class would have to expose) that in turn calls the callbacks of
 * any outstanding operations with a status of `CHIP_ERROR_CANCELLED`, and rejects any further calls
 * synchronously.
 */
class DLL_EXPORT NetworkIdentityRegistrar
{
public:
    virtual ~NetworkIdentityRegistrar() = default;

    /**
     * Retrieves the Network Identity of the network this registrar represents.
     * Maps onto the Network Identity Management cluster QueryIdentity command.
     */
    virtual CHIP_ERROR GetNetworkIdentity(Callback::Callback<OnNetworkIdentityAvailableFunct>::Owned onCompletion) = 0;

    /**
     * Grants the holder of the given Network Client Identity access to the network.
     * Maps onto the Network Identity Management cluster AddClient command.
     *
     * The commissioner keeps at most one registration outstanding at a time, and revokes it again
     * unless the commissionee ends up using the network it was granted access to, so a registrar
     * does not need to track pending registrations itself.
     *
     * @param clientIdentity Network Client Identity in compact-pdc-identity TLV format.
     */
    virtual CHIP_ERROR RegisterClient(ByteSpan clientIdentity, Callback::Callback<OnClientRegisteredFunct>::Owned onCompletion) = 0;

    /**
     * Revokes a previously granted access. Called when a later commissioning step fails, or
     * when the Wi-Fi network is abandoned in favour of another network technology.
     * Maps onto the Network Identity Management cluster RemoveClient command.
     *
     * Must be idempotent: the commissioner revokes a registration whose RegisterClient() call was
     * cancelled, because a cancelled call may still have taken effect on the network.
     *
     * The commissioner ignores the status it is given; a failure here leaves an entry that only an
     * out-of-band audit against the fabric can clean up. It waits for the completion where it needs
     * the revocation to be ordered against what it does next, and otherwise leaves the call running.
     *
     * @param clientIdentifier The key identifier of the client identity to revoke.
     */
    virtual CHIP_ERROR UnregisterClient(ByteSpan clientIdentifier,
                                        Callback::Callback<OnClientUnregisteredFunct>::Owned onCompletion) = 0;
};

} // namespace Controller
} // namespace chip
