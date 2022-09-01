/**
 *    Copyright (c) 2022 Project CHIP Authors
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

#import "Foundation/Foundation.h"

#include <app/BufferedReadCallback.h>
#include <app/ClusterStateCache.h>
#include <app/ConcreteAttributePath.h>
#include <app/EventHeader.h>
#include <app/MessageDef/StatusIB.h>
#include <app/ReadClient.h>
#include <app/ReadPrepareParams.h>
#include <lib/core/CHIPError.h>
#include <lib/core/CHIPTLV.h>
#include <lib/core/DataModelTypes.h>

#include <memory>

/**
 * This file defines a base class for subscription callbacks used by
 * MTRBaseDevice and MTRDevice.  This base class handles everything except the
 * actual conversion from the incoming data to the desired data.
 *
 * The desired data is assumed to be NSObjects that can be stored in NSArray.
 */

NS_ASSUME_NONNULL_BEGIN

typedef void (^DataReportCallback)(NSArray * value);
typedef void (^ErrorCallback)(NSError * error);
typedef void (^ResubscriptionCallback)(void);
typedef void (^SubscriptionEstablishedHandler)(void);
typedef void (^OnDoneHandler)(void);

class MTRBaseSubscriptionCallback : public chip::app::ClusterStateCache::Callback {
public:
    MTRBaseSubscriptionCallback(dispatch_queue_t queue, DataReportCallback attributeReportCallback,
        DataReportCallback eventReportCallback, ErrorCallback errorCallback,
        ResubscriptionCallback _Nullable resubscriptionCallback,
        SubscriptionEstablishedHandler _Nullable subscriptionEstablishedHandler, OnDoneHandler _Nullable onDoneHandler)
        : mQueue(queue)
        , mAttributeReportCallback(attributeReportCallback)
        , mEventReportCallback(eventReportCallback)
        , mErrorCallback(errorCallback)
        , mSubscriptionEstablishedHandler(subscriptionEstablishedHandler)
        , mResubscriptionCallback(resubscriptionCallback)
        , mBufferedReadAdapter(*this)
        , mOnDoneHandler(onDoneHandler)
    {
    }

    virtual ~MTRBaseSubscriptionCallback()
    {
        // Ensure we release the ReadClient before we tear down anything else,
        // so it can call our OnDeallocatePaths properly.
        mReadClient = nullptr;
    }

    chip::app::BufferedReadCallback & GetBufferedCallback() { return mBufferedReadAdapter; }

    // We need to exist to get a ReadClient, so can't take this as a constructor argument.
    void AdoptReadClient(std::unique_ptr<chip::app::ReadClient> aReadClient) { mReadClient = std::move(aReadClient); }
    void AdoptAttributeCache(std::unique_ptr<chip::app::ClusterStateCache> aAttributeCache)
    {
        mAttributeCache = std::move(aAttributeCache);
    }

protected:
    // Report an error, which may be due to issues in our own internal state or
    // due to the OnError callback happening.
    //
    // aCancelSubscription should be false for the OnError case, since it will
    // be immediately followed by OnDone and we want to do the deletion there.
    void ReportError(CHIP_ERROR aError, bool aCancelSubscription = true);

private:
    void OnReportBegin() override;

    void OnReportEnd() override;

    // OnEventData and OnAttributeData must be implemented by subclasses.
    void OnEventData(const chip::app::EventHeader & aEventHeader, chip::TLV::TLVReader * apData,
        const chip::app::StatusIB * apStatus) override = 0;

    void OnAttributeData(const chip::app::ConcreteDataAttributePath & aPath, chip::TLV::TLVReader * apData,
        const chip::app::StatusIB & aStatus) override = 0;

    void OnError(CHIP_ERROR aError) override;

    void OnDone(chip::app::ReadClient * aReadClient) override;

    void OnDeallocatePaths(chip::app::ReadPrepareParams && aReadPrepareParams) override;

    void OnSubscriptionEstablished(chip::SubscriptionId aSubscriptionId) override;

    CHIP_ERROR OnResubscriptionNeeded(chip::app::ReadClient * apReadClient, CHIP_ERROR aTerminationCause) override;

    void ReportData();

protected:
    NSMutableArray * _Nullable mAttributeReports = nil;
    NSMutableArray * _Nullable mEventReports = nil;

private:
    dispatch_queue_t mQueue;
    DataReportCallback _Nullable mAttributeReportCallback = nil;
    DataReportCallback _Nullable mEventReportCallback = nil;
    // We set mErrorCallback to nil when queueing error reports, so we
    // make sure to only report one error.
    ErrorCallback _Nullable mErrorCallback = nil;
    SubscriptionEstablishedHandler _Nullable mSubscriptionEstablishedHandler = nil;
    ResubscriptionCallback _Nullable mResubscriptionCallback = nil;
    chip::app::BufferedReadCallback mBufferedReadAdapter;

    // Our lifetime management is a little complicated.  On errors that don't
    // originate with the ReadClient we attempt to delete ourselves (and hence
    // the ReadClient), but asynchronously, because the ReadClient API doesn't
    // allow sync deletion under callbacks other than OnDone.  While that's
    // pending, something else (e.g. an error it runs into) could end up calling
    // OnDone on us.  And generally if OnDone is called we want to delete
    // ourselves as well.
    //
    // To handle this, enforce the following rules:
    //
    // 1) We guarantee that mErrorCallback is only invoked with an error once.
    // 2) We ensure that we delete ourselves and the passed in ReadClient only from OnDone or a queued-up
    //    error callback, but not both, by tracking whether we have a queued-up
    //    deletion.
    std::unique_ptr<chip::app::ReadClient> mReadClient;
    std::unique_ptr<chip::app::ClusterStateCache> mAttributeCache;
    bool mHaveQueuedDeletion = false;
    OnDoneHandler _Nullable mOnDoneHandler = nil;
};

NS_ASSUME_NONNULL_END
