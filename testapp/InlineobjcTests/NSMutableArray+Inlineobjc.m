//
//  NSMutableArray+Inlineobjc.m
//  Inlineobjc
//
//  Created by Resident evil on 7/31/15.
//  Copyright (c) 2015 Resident evil. All rights reserved.
//

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
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end

