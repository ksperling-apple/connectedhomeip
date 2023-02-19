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

#import "MTRCompletionGuard.h"

#import "MTRDefines_Internal.h"
#import "MTRError.h"

#import <os/lock.h>

NS_ASSUME_NONNULL_BEGIN

MTR_DIRECT_MEMBERS
@interface MTRCompletionGuard : NSObject
@end

MTR_DIRECT_MEMBERS
@implementation MTRCompletionGuard {
    os_unfair_lock _lock;
    MTRResultCompletion<id> _completion;
}

- (instancetype)initWithCompletion:(MTRResultCompletion<id>)completion
{
    if (self = [super init]) {
        _completion = completion;
    }
    return self;
}

- (MTRResultCompletion<id>)consumeCompletion
{
    os_unfair_lock_lock(&_lock);
    auto completion = _completion;
    _completion = nil;
    os_unfair_lock_unlock(&_lock);
    return completion;
}

- (void)dealloc
{
    auto completion = [self consumeCompletion];
    if (completion) {
        completion(nil, [NSError errorWithDomain:MTRErrorDomain code:MTRErrorCodeNotHandled userInfo:nil]);
    }
}

@end

MTRResultCompletion<id> _Nonnull _MTRGuardCompletion(MTRResultCompletion<id> _Nonnull completion)
{
    if (!completion) {
        return nil;
    }

    const auto guard = [[MTRCompletionGuard alloc] initWithCompletion:completion];
    return ^(id result, NSError * error) {
        auto completion = [guard consumeCompletion];
        if (!completion) {
            @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                           reason:@"Completion was already invoked"
                                         userInfo:nil];
        }
        completion(result, error);
    };
}

NS_ASSUME_NONNULL_END
