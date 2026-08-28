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

#include <controller/ControllerOperation.h>
#include <controller/NetworkIdentityRegistrar.h>
#include <credentials/CHIPCert.h>
#include <lib/core/CHIPCallback.h>
#include <lib/core/CHIPError.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/NodeId.h>
#include <lib/support/DLLUtil.h>
#include <lib/support/Span.h>

namespace chip {
namespace Controller {

/**
 * A NetworkIdentityRegistrar that drives the Network Identity Management cluster on a Network
 * Infrastructure Manager (NIM), using a borrowed DeviceController to reach it. (Note that this
 * may or may not be the same DeviceController that uses this registrar during commissioning.)
 *
 * Each operation independently obtains a CASE session to the NIM via the controller (relying on the
 * session caching in CASESessionManager) and then invokes a single command on it, so the registrar
 * holds no session of its own in between. Both the controller and the NIM node must remain valid
 * for the lifetime of the registrar.
 */
class DLL_EXPORT NetworkIdentityManagementRegistrar : public NetworkIdentityRegistrar
{
public:
    /**
     * @param controller  Controller used to reach the NIM. Borrowed; must outlive this object.
     * @param nodeId      Node ID of the NIM on the controller's fabric.
     * @param endpoint    Endpoint hosting the Network Identity Management cluster. There is no
     *                    fixed endpoint for it, so this has to be discovered or configured.
     */
    NetworkIdentityManagementRegistrar(DeviceController & controller, NodeId nodeId, EndpointId endpoint) :
        mController(controller), mNodeId(nodeId), mEndpoint(endpoint)
    {}
    ~NetworkIdentityManagementRegistrar() override;

    // Not copyable
    NetworkIdentityManagementRegistrar(const NetworkIdentityManagementRegistrar &)             = delete;
    NetworkIdentityManagementRegistrar & operator=(const NetworkIdentityManagementRegistrar &) = delete;

    /**
     * Completes whatever is in flight with CHIP_ERROR_CANCELLED and refuses further calls, so that
     * this registrar can be reclaimed without waiting for the network. Idempotent, and called by the
     * destructor, so an owner only needs it to reclaim one early.
     *
     * Reporting the outcome is the point of it: a caller that is waiting for a completion would
     * otherwise wait for one that can never arrive. That means arbitrary caller logic runs before this
     * returns -- from the destructor too -- so unwind anything of the caller's that refers to this
     * registrar first. See the NetworkIdentityRegistrar lifecycle documentation, which for a
     * DeviceCommissioner amounts to stopping the pairing that uses it.
     */
    void Shutdown();

    // NetworkIdentityRegistrar implementation
    CHIP_ERROR GetNetworkIdentity(Callback::Callback<OnNetworkIdentityAvailableFunct>::Owned onCompletion) override;
    CHIP_ERROR RegisterClient(ByteSpan clientIdentity, Callback::Callback<OnClientRegisteredFunct>::Owned onCompletion) override;
    CHIP_ERROR UnregisterClient(ByteSpan clientIdentifier,
                                Callback::Callback<OnClientUnregisteredFunct>::Owned onCompletion) override;

private:
    /**
     * What our three operations have in common: each connects to the NIM, invokes a single command
     * on it, and reports anything that stops it getting an answer back to the caller.
     */
    class Operation : public ControllerInvokeOperationBase
    {
    public:
        /**
         * Completes the operation with the given failure status if it is in flight, and does nothing
         * otherwise. This is how Shutdown() discharges the obligation to report an outcome, and it
         * tolerates an operation a previous completion already dealt with re-entrantly.
         */
        void FailIfPending(CHIP_ERROR error)
        {
            if (IsPending())
            {
                Fail(error);
            }
        }

    protected:
        virtual CHIP_ERROR SendCommand(Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session) = 0;

        // Completes the operation with a failure status, whatever its completion signature is.
        virtual void Fail(CHIP_ERROR error) = 0;

    private:
        void OnConnected(Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session) final;
        void OnConnectionFailure(CHIP_ERROR error) final;
    };

    using QueryIdentityOperationBase = Callback::TypedOperation<Operation, CHIP_ERROR, ByteSpan>;
    using StatusOperationBase        = Callback::TypedOperation<Operation, CHIP_ERROR>;

    class QueryIdentityOperation final : public QueryIdentityOperationBase
    {
    public:
        using QueryIdentityOperationBase::Start;

    private:
        CHIP_ERROR SendCommand(Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session) override;
        void Fail(CHIP_ERROR error) override { Complete(error, ByteSpan()); }
    };

    class AddClientOperation final : public StatusOperationBase
    {
    public:
        /// Takes a copy of the identity, since the caller's span does not outlive the call.
        CHIP_ERROR Begin(DeviceController & controller, NodeId nodeId, EndpointId endpoint, ByteSpan clientIdentity,
                         Completion::Owned onCompletion);

    private:
        CHIP_ERROR SendCommand(Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session) override;
        void Fail(CHIP_ERROR error) override { Complete(error); }

        uint8_t mClientIdentity[Credentials::kMaxCHIPCompactNetworkIdentityLength];
        uint8_t mClientIdentityLength = 0;
    };

    class RemoveClientOperation final : public StatusOperationBase
    {
    public:
        /// Takes a copy of the identifier, since the caller's span does not outlive the call.
        CHIP_ERROR Begin(DeviceController & controller, NodeId nodeId, EndpointId endpoint, ByteSpan clientIdentifier,
                         Completion::Owned onCompletion);

    private:
        CHIP_ERROR SendCommand(Messaging::ExchangeManager & exchangeMgr, const SessionHandle & session) override;
        void Fail(CHIP_ERROR error) override { Complete(error); }

        Credentials::CertificateKeyIdStorage mClientIdentifier;
    };

    // GetNetworkIdentity() and RegisterClient() share a slot, since the caller only ever has one of
    // the two in flight at a time. A revocation may overlap either of them.
    bool RequestInFlight() const { return mQueryIdentity.IsPending() || mAddClient.IsPending(); }

    DeviceController & mController;
    const NodeId mNodeId;
    const EndpointId mEndpoint;

    // Set by Shutdown(), and never cleared: a registrar that has reported its calls as cancelled
    // cannot take on new ones, and is only waiting to be destroyed.
    bool mShutDown = false;

    QueryIdentityOperation mQueryIdentity;
    AddClientOperation mAddClient;
    RemoveClientOperation mRemoveClient;
};

} // namespace Controller
} // namespace chip
