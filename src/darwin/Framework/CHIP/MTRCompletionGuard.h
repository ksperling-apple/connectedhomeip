/**
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

#import <Foundation/Foundation.h>
#import <Matter/MTRDefines.h>

NS_ASSUME_NONNULL_BEGIN

template <typename ResultType> using MTRResultCompletion = void (^)(ResultType _Nullable result, NSError * _Nullable error);

/**
 * Wraps a completion block to guard it against misuse.
 *
 * Calling the guarded block more than once results in an exception. Abandoning
 * the guarded block without calling it will call the underlying block with an
 * `MTRErrorCodeNotHandled` error.
 */
template <typename ResultType>
inline MTRResultCompletion<ResultType> _Nonnull MTRGuardCompletion(MTRResultCompletion<ResultType> _Nonnull completion);

#pragma mark - Implementation

MTR_EXTERN MTRResultCompletion<id> _Nonnull _MTRGuardCompletion(MTRResultCompletion<id> _Nonnull completion);

template <typename ResultType>
inline MTRResultCompletion<ResultType> _Nonnull MTRGuardCompletion(MTRResultCompletion<ResultType> _Nonnull completion)
{
    // Implement via type erasure for object pointer ResultTypes
    return _MTRGuardCompletion(static_cast<MTRResultCompletion<id>>(completion));
}

NS_ASSUME_NONNULL_END
