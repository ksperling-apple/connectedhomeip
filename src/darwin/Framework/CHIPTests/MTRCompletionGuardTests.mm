//
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
#import "MTRError.h"

#import <XCTest/XCTest.h>

@interface MTRCompletionGuardTests : XCTestCase
@end

@implementation MTRCompletionGuardTests

- (void)testCompletionBlockInvoked
{
    __block BOOL invoked = NO;
    NSData * theResult = [[NSMutableData alloc] init];
    NSError * theError = [NSError errorWithDomain:MTRErrorDomain code:MTRErrorCodeGeneralError userInfo:nil];
    auto completion = ^(NSData * result, NSError * error) {
        XCTAssertIdentical(result, theResult);
        XCTAssertIdentical(error, theError);
        invoked = YES;
    };
    auto guardedCompletion = MTRGuardCompletion(completion);
    guardedCompletion(theResult, theError);
    XCTAssertTrue(invoked);
}

- (void)testCompletionBlockInvokedTwice
{
    auto guardedCompletion = MTRGuardCompletion(^(id result, NSError * error) {
        /* nothing */
    });
    guardedCompletion(@"hello", nil);
    XCTAssertThrows(guardedCompletion(@"hello again", nil));
}

- (void)testCompletionNotInvoked
{
    XCTestExpectation * invoked = [self expectationWithDescription:@"completion invoked"];
    @autoreleasepool {
        [self delegateMethodThatDoesNotInvokeCompletion:MTRGuardCompletion(^(NSString * result, NSError * error) {
            XCTAssertNil(result);
            XCTAssertNotNil(error);
            XCTAssertEqualObjects(error.domain, MTRErrorDomain);
            XCTAssertEqual(error.code, MTRErrorCodeNotHandled);
            [invoked fulfill];
        })];
    }
    [self waitForExpectationsWithTimeout:1 handler:nil];
}

- (void)delegateMethodThatDoesNotInvokeCompletion:(void (^)(NSString * result, NSError * error))completion
{
    // do nothing
}

@end
