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

#include "DefaultThreadNetworkDirectoryStorage.h"
#include <app/clusters/thread-network-directory-server/DefaultThreadNetworkDirectoryStorage.h>

namespace chip {
namespace app {

DefaultThreadNetworkDirectoryStorage::DefaultThreadNetworkDirectoryStorage(PersistentStorageDelegate & storage) : mStorage(storage)
{}

ThreadNetworkDirectoryStorage::ExtendedPanIdIterator * DefaultThreadNetworkDirectoryStorage::IterateNetworkIds()
{
    return nullptr;
}

CHIP_ERROR DefaultThreadNetworkDirectoryStorage::GetNetworkDataset(ExtendedPanId exPanId, MutableByteSpan & dataset)
{
    return CHIP_ERROR_NOT_FOUND;
}

CHIP_ERROR DefaultThreadNetworkDirectoryStorage::AddOrUpdateNetwork(ExtendedPanId exPanId, ByteSpan dataset)
{
    (void) mStorage;
    return CHIP_ERROR_NO_MEMORY;
}

CHIP_ERROR DefaultThreadNetworkDirectoryStorage::RemoveNetwork(ExtendedPanId exPanId)
{
    return CHIP_ERROR_NOT_FOUND;
}

} // namespace app
} // namespace chip
