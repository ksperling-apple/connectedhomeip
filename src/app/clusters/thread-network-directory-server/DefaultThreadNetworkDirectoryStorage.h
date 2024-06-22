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

#pragma once

#include <app/clusters/thread-network-directory-server/ThreadNetworkDirectoryStorage.h>
#include <lib/core/CHIPPersistentStorageDelegate.h>

namespace chip {
namespace app {

/**
 * Stores Thread network information via a PersistentStorageDelegate.
 */
class DefaultThreadNetworkDirectoryStorage : public ThreadNetworkDirectoryStorage
{
public:
    DefaultThreadNetworkDirectoryStorage(PersistentStorageDelegate & storage);

    ExtendedPanIdIterator * IterateNetworkIds() override;
    CHIP_ERROR GetNetworkDataset(ExtendedPanId exPanId, MutableByteSpan & dataset) override;
    CHIP_ERROR AddOrUpdateNetwork(ExtendedPanId exPanId, ByteSpan dataset) override;
    CHIP_ERROR RemoveNetwork(ExtendedPanId exPanId) override;

private:
    PersistentStorageDelegate & mStorage;
};

} // namespace app
} // namespace chip
