/**
 *
 *    Copyright (c) 2024 Project CHIP Authors
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

#include "thread-network-directory-server.h"

#include <app/AttributeAccessInterfaceRegistry.h>
#include <app/InteractionModelEngine.h>
#include <app/reporting/reporting.h>
#include <lib/support/CodeUtils.h>

using namespace chip;
using namespace chip::app;
using namespace chip::app::Clusters;
using namespace chip::app::Clusters::ThreadNetworkDirectory::Attributes;
using namespace chip::app::Clusters::ThreadNetworkDirectory::Commands;

namespace chip {
namespace app {
namespace Clusters {

ThreadNetworkDirectoryServer::ThreadNetworkDirectoryServer(EndpointId endpoint, ThreadNetworkDirectoryStorage & storage) :
    AttributeAccessInterface(NullOptional, ThreadNetworkDirectory::Id),
    CommandHandlerInterface(NullOptional, ThreadNetworkDirectory::Id), mStorage(storage)
{}

ThreadNetworkDirectoryServer::~ThreadNetworkDirectoryServer()
{
    unregisterAttributeAccessOverride(this);
    InteractionModelEngine::GetInstance()->UnregisterCommandHandler(this);
}

CHIP_ERROR ThreadNetworkDirectoryServer::Init()
{
    VerifyOrReturnError(registerAttributeAccessOverride(this), CHIP_ERROR_INTERNAL);
    ReturnErrorOnFailure(InteractionModelEngine::GetInstance()->RegisterCommandHandler(this));
    return CHIP_NO_ERROR;
}

CHIP_ERROR ThreadNetworkDirectoryServer::Read(const ConcreteReadAttributePath & aPath, AttributeValueEncoder & aEncoder)
{
    switch (aPath.mAttributeId)
    {
    case PreferredExtendedPanID::Id:
        return aEncoder.EncodeNull();
    case ThreadNetworks::Id:
        return aEncoder.EncodeNull();
    }
    return CHIP_NO_ERROR;
}

void ThreadNetworkDirectoryServer::InvokeCommand(HandlerContext & ctx)
{
    switch (ctx.mRequestPath.mCommandId)
    {
    case AddNetwork::Id:
        HandleCommand<AddNetwork::DecodableType>(
            ctx, [this](HandlerContext & aCtx, const auto & req) { HandleAddNetworkRequest(aCtx, req); });
        return;
    case RemoveNetwork::Id:
        HandleCommand<RemoveNetwork::DecodableType>(
            ctx, [this](HandlerContext & aCtx, const auto & req) { HandleRemoveNetworkRequest(aCtx, req); });
        return;
    case GetOperationalDataset::Id:
        HandleCommand<GetOperationalDataset::DecodableType>(
            ctx, [this](HandlerContext & aCtx, const auto & req) { HandleOperationalDatasetRequest(aCtx, req); });
        return;
    }
}

void ThreadNetworkDirectoryServer::HandleAddNetworkRequest(HandlerContext & ctx,
                                                           const ThreadNetworkDirectory::Commands::AddNetwork::DecodableType & req)
{
    ctx.mCommandHandler.AddStatus(ctx.mRequestPath, Protocols::InteractionModel::Status::UnsupportedCommand);
}

void ThreadNetworkDirectoryServer::HandleRemoveNetworkRequest(
    HandlerContext & ctx, const ThreadNetworkDirectory::Commands::RemoveNetwork::DecodableType & req)
{
    ctx.mCommandHandler.AddStatus(ctx.mRequestPath, Protocols::InteractionModel::Status::UnsupportedCommand);
}

void ThreadNetworkDirectoryServer::HandleOperationalDatasetRequest(
    HandlerContext & ctx, const ThreadNetworkDirectory::Commands::GetOperationalDataset::DecodableType & req)
{
    ctx.mCommandHandler.AddStatus(ctx.mRequestPath, Protocols::InteractionModel::Status::UnsupportedCommand);
}

} // namespace Clusters
} // namespace app
} // namespace chip

void MatterThreadNetworkDirectoryPluginServerInitCallback() {}
