/*
 *   Copyright (c) 2015 - 2016 Kulykov Oleh <info@resident.name>
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
#import "NSMutableArray+Inlineobjc.h"

@interface NSMutableArray_Inlineobjc : XCTestCase

@end

@implementation NSMutableArray_Inlineobjc

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

	// NSMutableArrayAppendUniqObjectUnsafe
	NSMutableArray * dst1 = [NSMutableArray array];
	NSMutableArray * dst2 = [NSMutableArray array];
	for (id obj in @[ @(-2), @(-1), @(0), @(1), @(2) ])
	{
		NSMutableArrayAppendUniqObjectUnsafe(dst1, obj);
		NSMutableArrayAppendUniqObjectSafe(dst2, obj);
	}
	BOOL res = [dst1 isEqualToArray:@[@(-2), @(-1), @(0), @(1), @(2)]];
	XCTAssert(res, @"ERROR NSMutableArrayAppendUniqObjectUnsafe");
	XCTAssert([dst1 isEqualToArray:dst2], @"ERROR NSMutableArrayAppendUniqObjectSafe");
	[dst1 removeAllObjects];
	[dst2 removeAllObjects];

	for (id obj in @[ @(-1), @(-1), @(0), @(1), @(2) ])
	{
		NSMutableArrayAppendUniqObjectUnsafe(dst1, obj);
		NSMutableArrayAppendUniqObjectSafe(dst2, obj);
	}
	res = [dst1 isEqualToArray:@[@(-1), @(0), @(1), @(2)]];
	XCTAssert(res, @"ERROR NSMutableArrayAppendUniqObjectUnsafe");
	XCTAssert([dst1 isEqualToArray:dst2], @"ERROR NSMutableArrayAppendUniqObjectSafe");
	[dst1 removeAllObjects];
	[dst2 removeAllObjects];


	// NSMutableArrayPrependUniqObjectUnsafe
	for (id obj in @[ @(-2), @(-1), @(0), @(1), @(2) ])
	{
		NSMutableArrayPrependUniqObjectUnsafe(dst1, obj);
		NSMutableArrayPrependUniqObjectSafe(dst2, obj);
	}
	res = [dst1 isEqualToArray:@[@(2), @(1), @(0), @(-1), @(-2)]];
	XCTAssert(res, @"ERROR NSMutableArrayPrependUniqObjectUnsafe");
	XCTAssert([dst1 isEqualToArray:dst2], @"ERROR NSMutableArrayPrependUniqObjectSafe");
	[dst1 removeAllObjects];
	[dst2 removeAllObjects];

	for (id obj in @[ @(-1), @(-1), @(0), @(1), @(2) ])
	{
		NSMutableArrayPrependUniqObjectUnsafe(dst1, obj);
		NSMutableArrayPrependUniqObjectSafe(dst2, obj);
	}
	res = [dst1 isEqualToArray:@[@(2), @(1), @(0), @(-1)]];
	XCTAssert(res, @"ERROR NSMutableArrayPrependUniqObjectUnsafe");
	XCTAssert([dst1 isEqualToArray:dst2], @"ERROR NSMutableArrayPrependUniqObjectSafe");
	[dst1 removeAllObjects];
	[dst2 removeAllObjects];


	// NSMutableArrayAppendUniqSafe
	// NSMutableArrayPrependUniqSafe

	NSMutableArrayAppendUniqSafe(dst1, @[ @(-1), @(-1), @(0), @(1), @(2) ]);
	res = [dst1 isEqualToArray:@[@(-1), @(0), @(1), @(2)]];
	XCTAssert(res, @"ERROR NSMutableArrayAppendUniqSafe");


	NSMutableArrayPrependUniqSafe(dst2, @[ @(-1), @(-1), @(0), @(1), @(2) ]);
	res = [dst2 isEqualToArray:@[@(2), @(1), @(0), @(-1)]];
	XCTAssert(res, @"ERROR NSMutableArrayAppendUniqSafe");

	[dst1 removeAllObjects];
	[dst2 removeAllObjects];

	NSMutableArrayAppendSafe(dst1, @[@(0),@(1),@(2)]);
	res = [dst1 isEqualToArray:@[@(0),@(1),@(2)]];
	XCTAssert(res, @"ERROR NSMutableArrayAppendSafe");

	[dst1 removeAllObjects];

	NSMutableArrayPrependSafe(dst1, @[@(0),@(1),@(2)]);
	res = [dst1 isEqualToArray:@[@(2),@(1),@(0)]];
	XCTAssert(res, @"ERROR NSMutableArrayPrependSafe");

	[dst1 removeAllObjects];
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end

