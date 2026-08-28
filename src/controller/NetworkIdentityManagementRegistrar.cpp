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

#include <controller/NetworkIdentityManagementRegistrar.h>

#include <app/ConcreteCommandPath.h>
#include <app/data-model/NullObject.h>
#include <clusters/NetworkIdentityManagement/Commands.h>
#include <clusters/NetworkIdentityManagement/Enums.h>
#include <lib/core/CHIPError.h>
#include <lib/core/Optional.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#include <cstring>
#include <utility>

namespace chip {
namespace Controller {

using namespace app::Clusters::NetworkIdentityManagement;

namespace {

// AddClient and RemoveClient are timed invokes.
constexpr uint16_t kTimedInvokeTimeoutMs = 10000;

} // namespace

NetworkIdentityManagementRegistrar::~NetworkIdentityManagementRegistrar()
{
    // An operation still in flight means we are being destroyed before the commissioning attempt we
    // were supplied for has ended, which the NetworkIdentityRegistrar contract forbids. Say so, and
    // shut down regardless: an operation destroyed while pending dies on its own assertion, and
    // would leave a CommandSender and the caller's callback pointing at freed memory besides.
    if (!mShutDown && (RequestInFlight() || mRemoveClient.IsPending()))
    {
        ChipLogError(Controller, "Network Identity Management registrar destroyed with an operation still in flight");
    }
    Shutdown();
}

void NetworkIdentityManagementRegistrar::Shutdown()
{
    // Refuse further calls before completing anything: a callback below is free to try to start
    // another operation, and there is nothing left of us to start it with. This is also what keeps a
    // caller that re-enters us from the destructor from operating on a half-destroyed object.
    mShutDown = true;

    // Reporting is not optional: a caller waiting on a completion would otherwise wait for one that
    // can never arrive. Each of these checks whether the operation is still in flight, so a callback
    // that re-enters Shutdown() and completes the remaining ones is harmless.
    mQueryIdentity.FailIfPending(CHIP_ERROR_CANCELLED);
    mAddClient.FailIfPending(CHIP_ERROR_CANCELLED);
    mRemoveClient.FailIfPending(CHIP_ERROR_CANCELLED);
}

CHIP_ERROR
NetworkIdentityManagementRegistrar::GetNetworkIdentity(Callback::Callback<OnNetworkIdentityAvailableFunct>::Owned onCompletion)
{
    VerifyOrReturnError(!mShutDown, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(!RequestInFlight(), CHIP_ERROR_INCORRECT_STATE);

    mQueryIdentity.Start(mController, mNodeId, mEndpoint, std::move(onCompletion));
    return CHIP_NO_ERROR;
}

CHIP_ERROR NetworkIdentityManagementRegistrar::RegisterClient(ByteSpan clientIdentity,
                                                              Callback::Callback<OnClientRegisteredFunct>::Owned onCompletion)
{
    VerifyOrReturnError(!mShutDown, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(!RequestInFlight(), CHIP_ERROR_INCORRECT_STATE);

    return mAddClient.Begin(mController, mNodeId, mEndpoint, clientIdentity, std::move(onCompletion));
}

CHIP_ERROR NetworkIdentityManagementRegistrar::UnregisterClient(ByteSpan clientIdentifier,
                                                                Callback::Callback<OnClientUnregisteredFunct>::Owned onCompletion)
{
    VerifyOrReturnError(!mShutDown, CHIP_ERROR_INCORRECT_STATE);

    // A caller only ever has one registration to give up at a time, so a revocation already in
    // flight means it is not playing by the rules, and there is no point in queueing this one up
    // behind the one it forgot about.
    VerifyOrReturnError(!mRemoveClient.IsPending(), CHIP_ERROR_INCORRECT_STATE);

    return mRemoveClient.Begin(mController, mNodeId, mEndpoint, clientIdentifier, std::move(onCompletion));
}

void NetworkIdentityManagementRegistrar::Operation::OnConnected(Messaging::ExchangeManager & exchangeMgr,
                                                                const SessionHandle & session)
{
    CHIP_ERROR err = SendCommand(exchangeMgr, session);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogFailure(err, Controller, "Failed to send Network Identity Management command");
        Fail(err);
    }
}

void NetworkIdentityManagementRegistrar::Operation::OnConnectionFailure(CHIP_ERROR error)
{
    ChipLogFailure(error, Controller, "Failed to establish a session with the Network Infrastructure Manager");
    Fail(error);
}

CHIP_ERROR NetworkIdentityManagementRegistrar::QueryIdentityOperation::SendCommand(Messaging::ExchangeManager & exchangeMgr,
                                                                                   const SessionHandle & session)
{
    // Ask for the network's current identity of the only type PDC defines, rather than for a
    // specific entry in the NIM's table: which one is current is up to the NIM.
    Commands::QueryIdentity::Type request;
    request.networkIdentityType.Emplace(IdentityTypeEnum::kEcdsa);

    return Invoke(
        exchangeMgr, session, request,
        [this](const app::ConcreteCommandPath &, const app::StatusIB &,
               const Commands::QueryIdentityResponse::DecodableType & response) {
            // The identity points into the response message, which is exactly as long-lived as the
            // OnNetworkIdentityAvailable callback needs it to be.
            Complete(CHIP_NO_ERROR, response.identity);
        },
        [this](CHIP_ERROR error) { Fail(error); });
}

CHIP_ERROR NetworkIdentityManagementRegistrar::AddClientOperation::Begin(DeviceController & controller, NodeId nodeId,
                                                                         EndpointId endpoint, ByteSpan clientIdentity,
                                                                         Completion::Owned onCompletion)
{
    // Reject before starting, since an error return promises that no completion is coming. This is
    // also why the identity buffer is only touched once we know we are taking the call on.
    VerifyOrReturnError(clientIdentity.size() <= sizeof(mClientIdentity), CHIP_ERROR_INVALID_ARGUMENT);
    memcpy(mClientIdentity, clientIdentity.data(), clientIdentity.size());
    mClientIdentityLength = static_cast<uint8_t>(clientIdentity.size());

    Start(controller, nodeId, endpoint, std::move(onCompletion));
    return CHIP_NO_ERROR;
}

CHIP_ERROR NetworkIdentityManagementRegistrar::AddClientOperation::SendCommand(Messaging::ExchangeManager & exchangeMgr,
                                                                               const SessionHandle & session)
{
    Commands::AddClient::Type request;
    request.clientIdentity = ByteSpan(mClientIdentity, mClientIdentityLength);

    return Invoke(
        exchangeMgr, session, request,
        [this](const app::ConcreteCommandPath &, const app::StatusIB &,
               const Commands::AddClientResponse::DecodableType & response) {
            ChipLogProgress(Controller, "Network Client Identity registered at client index %u", response.clientIndex);
            Complete(CHIP_NO_ERROR);
        },
        [this](CHIP_ERROR error) { Fail(error); }, MakeOptional(kTimedInvokeTimeoutMs));
}

CHIP_ERROR NetworkIdentityManagementRegistrar::RemoveClientOperation::Begin(DeviceController & controller, NodeId nodeId,
                                                                            EndpointId endpoint, ByteSpan clientIdentifier,
                                                                            Completion::Owned onCompletion)
{
    // Reject before starting, since an error return promises that no completion is coming.
    VerifyOrReturnError(clientIdentifier.size() == mClientIdentifier.size(), CHIP_ERROR_INVALID_ARGUMENT);
    memcpy(mClientIdentifier.data(), clientIdentifier.data(), clientIdentifier.size());

    Start(controller, nodeId, endpoint, std::move(onCompletion));
    return CHIP_NO_ERROR;
}

CHIP_ERROR NetworkIdentityManagementRegistrar::RemoveClientOperation::SendCommand(Messaging::ExchangeManager & exchangeMgr,
                                                                                  const SessionHandle & session)
{
    Commands::RemoveClient::Type request;
    request.clientIdentifier.Emplace(ByteSpan(mClientIdentifier));

    return Invoke(
        exchangeMgr, session, request,
        [this](const app::ConcreteCommandPath &, const app::StatusIB &, const app::DataModel::NullObjectType &) {
            ChipLogProgress(Controller, "Network Client Identity revoked");
            Complete(CHIP_NO_ERROR);
        },
        [this](CHIP_ERROR error) {
            if (error == CHIP_IM_GLOBAL_STATUS(NotFound))
            {
                // Revocation is required to be idempotent, so this is a success as far as we care.
                ChipLogDetail(Controller, "Network Client Identity was already revoked");
                Complete(CHIP_NO_ERROR);
                return;
            }
            ChipLogFailure(error, Controller, "Failed to revoke Network Client Identity");
            Fail(error);
        },
        MakeOptional(kTimedInvokeTimeoutMs));
}

} // namespace Controller
} // namespace chip
