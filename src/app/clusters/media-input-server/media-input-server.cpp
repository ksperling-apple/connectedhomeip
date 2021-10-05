/**
 *
 *    Copyright (c) 2021 Project CHIP Authors
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
/****************************************************************************
 * @file
 * @brief Routines for the Media Input plugin, the
 *server implementation of the Media Input cluster.
 *******************************************************************************
 ******************************************************************************/

#include <app-common/zap-generated/attribute-id.h>
#include <app-common/zap-generated/attribute-type.h>
#include <app-common/zap-generated/cluster-id.h>
#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/command-id.h>
#include <app/CommandHandler.h>
#include <app/ConcreteCommandPath.h>
#include <app/util/af.h>
#include <string>

using namespace chip;
using namespace chip::app::Clusters::MediaInput;

bool mediaInputClusterSelectInput(uint8_t input);
bool mediaInputClusterShowInputStatus();
bool mediaInputClusterHideInputStatus();
bool mediaInputClusterRenameInput(uint8_t input, std::string name);

static void storeCurrentInput(EndpointId endpoint, uint8_t currentInput)
{
    EmberAfStatus status = emberAfWriteServerAttribute(
        endpoint, ZCL_MEDIA_INPUT_CLUSTER_ID, ZCL_MEDIA_INPUT_CURRENT_INPUT_ATTRIBUTE_ID, &currentInput, ZCL_INT8U_ATTRIBUTE_TYPE);
    if (status != EMBER_ZCL_STATUS_SUCCESS)
    {
        ChipLogError(Zcl, "Failed to store media playback attribute.");
    }
}

bool emberAfMediaInputClusterSelectInputCallback(app::CommandHandler * command, const app::ConcreteCommandPath & commandPath,
                                                 EndpointId endpoint, uint8_t input,
                                                 Commands::SelectInput::DecodableType & commandData)
{
    bool success         = mediaInputClusterSelectInput(input);
    EmberAfStatus status = success ? EMBER_ZCL_STATUS_SUCCESS : EMBER_ZCL_STATUS_FAILURE;
    if (success)
    {
        storeCurrentInput(emberAfCurrentEndpoint(), input);
    }
    emberAfSendImmediateDefaultResponse(status);
    return true;
}

bool emberAfMediaInputClusterShowInputStatusCallback(app::CommandHandler * command, const app::ConcreteCommandPath & commandPath,
                                                     EndpointId endpoint, Commands::ShowInputStatus::DecodableType & commandData)
{
    bool success         = mediaInputClusterShowInputStatus();
    EmberAfStatus status = success ? EMBER_ZCL_STATUS_SUCCESS : EMBER_ZCL_STATUS_FAILURE;
    emberAfSendImmediateDefaultResponse(status);
    return true;
}

bool emberAfMediaInputClusterHideInputStatusCallback(app::CommandHandler * command, const app::ConcreteCommandPath & commandPath,
                                                     EndpointId endpoint, Commands::HideInputStatus::DecodableType & commandData)
{
    bool success         = mediaInputClusterHideInputStatus();
    EmberAfStatus status = success ? EMBER_ZCL_STATUS_SUCCESS : EMBER_ZCL_STATUS_FAILURE;
    emberAfSendImmediateDefaultResponse(status);
    return true;
}

bool emberAfMediaInputClusterRenameInputCallback(app::CommandHandler * command, const app::ConcreteCommandPath & commandPath,
                                                 EndpointId endpoint, uint8_t input, uint8_t * name,
                                                 Commands::RenameInput::DecodableType & commandData)
{
    // TODO: char is not null terminated, verify this code once #7963 gets merged.
    std::string nameString(reinterpret_cast<char *>(name));
    bool success         = mediaInputClusterRenameInput(input, nameString);
    EmberAfStatus status = success ? EMBER_ZCL_STATUS_SUCCESS : EMBER_ZCL_STATUS_FAILURE;
    emberAfSendImmediateDefaultResponse(status);
    return true;
}
