/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

package matter.devicecontroller.cluster.clusters

import java.util.ArrayList

class LaundryWasherModeCluster(private val endpointId: UShort) {
  class ChangeToModeResponse(val status: UInt, val statusText: String?)

  class SupportedModesAttribute(
    val value: ArrayList<ChipStructs.LaundryWasherModeClusterModeOptionStruct>
  )

  class StartUpModeAttribute(val value: UByte?)

  class OnModeAttribute(val value: UByte?)

  class GeneratedCommandListAttribute(val value: ArrayList<UInt>)

  class AcceptedCommandListAttribute(val value: ArrayList<UInt>)

  class EventListAttribute(val value: ArrayList<UInt>)

  class AttributeListAttribute(val value: ArrayList<UInt>)

  suspend fun changeToMode(
    newMode: UByte,
    timedInvokeTimeoutMs: Int? = null
  ): ChangeToModeResponse {
    if (timedInvokeTimeoutMs != null) {
      // Do the action with timedInvokeTimeoutMs
    } else {
      // Do the action without timedInvokeTimeoutMs
    }
  }

  suspend fun readSupportedModesAttribute(): SupportedModesAttribute {
    // Implementation needs to be added here
  }

  suspend fun subscribeSupportedModesAttribute(
    minInterval: Int,
    maxInterval: Int
  ): SupportedModesAttribute {
    // Implementation needs to be added here
  }

  suspend fun readCurrentModeAttribute(): UByte {
    // Implementation needs to be added here
  }

  suspend fun subscribeCurrentModeAttribute(minInterval: Int, maxInterval: Int): UByte {
    // Implementation needs to be added here
  }

  suspend fun readStartUpModeAttribute(): StartUpModeAttribute {
    // Implementation needs to be added here
  }

  suspend fun writeStartUpModeAttribute(value: UByte) {
    // Implementation needs to be added here
  }

  suspend fun writeStartUpModeAttribute(value: UByte, timedWriteTimeoutMs: Int) {
    // Implementation needs to be added here
  }

  suspend fun subscribeStartUpModeAttribute(
    minInterval: Int,
    maxInterval: Int
  ): StartUpModeAttribute {
    // Implementation needs to be added here
  }

  suspend fun readOnModeAttribute(): OnModeAttribute {
    // Implementation needs to be added here
  }

  suspend fun writeOnModeAttribute(value: UByte) {
    // Implementation needs to be added here
  }

  suspend fun writeOnModeAttribute(value: UByte, timedWriteTimeoutMs: Int) {
    // Implementation needs to be added here
  }

  suspend fun subscribeOnModeAttribute(minInterval: Int, maxInterval: Int): OnModeAttribute {
    // Implementation needs to be added here
  }

  suspend fun readGeneratedCommandListAttribute(): GeneratedCommandListAttribute {
    // Implementation needs to be added here
  }

  suspend fun subscribeGeneratedCommandListAttribute(
    minInterval: Int,
    maxInterval: Int
  ): GeneratedCommandListAttribute {
    // Implementation needs to be added here
  }

  suspend fun readAcceptedCommandListAttribute(): AcceptedCommandListAttribute {
    // Implementation needs to be added here
  }

  suspend fun subscribeAcceptedCommandListAttribute(
    minInterval: Int,
    maxInterval: Int
  ): AcceptedCommandListAttribute {
    // Implementation needs to be added here
  }

  suspend fun readEventListAttribute(): EventListAttribute {
    // Implementation needs to be added here
  }

  suspend fun subscribeEventListAttribute(minInterval: Int, maxInterval: Int): EventListAttribute {
    // Implementation needs to be added here
  }

  suspend fun readAttributeListAttribute(): AttributeListAttribute {
    // Implementation needs to be added here
  }

  suspend fun subscribeAttributeListAttribute(
    minInterval: Int,
    maxInterval: Int
  ): AttributeListAttribute {
    // Implementation needs to be added here
  }

  suspend fun readFeatureMapAttribute(): UInt {
    // Implementation needs to be added here
  }

  suspend fun subscribeFeatureMapAttribute(minInterval: Int, maxInterval: Int): UInt {
    // Implementation needs to be added here
  }

  suspend fun readClusterRevisionAttribute(): UShort {
    // Implementation needs to be added here
  }

  suspend fun subscribeClusterRevisionAttribute(minInterval: Int, maxInterval: Int): UShort {
    // Implementation needs to be added here
  }

  companion object {
    const val CLUSTER_ID: UInt = 81u
  }
}