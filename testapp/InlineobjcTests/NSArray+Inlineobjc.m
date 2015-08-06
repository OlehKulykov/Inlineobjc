/*
 *   Copyright (c) 2015 Kulykov Oleh <info@resident.name>
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */


#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "NSArray+Inlineobjc.h"

@interface NSArray_Inlineobjc : XCTestCase

@end

@implementation NSArray_Inlineobjc

- (void)setUp
{
	[super setUp];
	// Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
	// Put teardown code here. This method is called after the invocation of each test method in the class.
	[super tearDown];
}

- (void)testExample
{
	// This is an example of a functional test case.
	XCTAssert(NSArrayIsEmpty(nil), @"ERROR NSArrayIsEmpty");
	XCTAssert(NSArrayIsEmpty(@[]), @"ERROR NSArrayIsEmpty");
	XCTAssert(!NSArrayIsEmpty(@[ @(0) ]), @"ERROR NSArrayIsEmpty");

	XCTAssert(NSArrayIsNotEmpty(@[ @(0) ]), @"ERROR NSArrayIsNotEmpty");
	XCTAssert(!NSArrayIsNotEmpty(@[]), @"ERROR NSArrayIsNotEmpty");
	XCTAssert(!NSArrayIsNotEmpty(nil), @"ERROR NSArrayIsNotEmpty");

	XCTAssert(NSArrayCount(@[ @(0) ]) == 1, @"ERROR NSArrayCount");
	XCTAssert(NSArrayCount(@[]) == 0, @"ERROR NSArrayCount");
	XCTAssert(NSArrayCount(nil) == 0, @"ERROR NSArrayCount");


	XCTAssert(NSArrayObjectAtIndex(@[ @(0) ], 0) != nil, @"ERROR NSArrayObjectAtIndex");
	XCTAssert(NSArrayObjectAtIndex(@[ @(0) ], 4) == nil, @"ERROR NSArrayObjectAtIndex");
	XCTAssert(NSArrayObjectAtIndex(@[], 0) == nil, @"ERROR NSArrayObjectAtIndex");
	XCTAssert(NSArrayObjectAtIndex(nil, 0) == nil, @"ERROR NSArrayObjectAtIndex");
	XCTAssert(NSArrayObjectAtIndex(@[], 4) == nil, @"ERROR NSArrayObjectAtIndex");
	XCTAssert(NSArrayObjectAtIndex(nil, 5) == nil, @"ERROR NSArrayObjectAtIndex");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end
