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


	NSMutableArray * arrayA = [NSMutableArray array];
	NSMutableArray * arrayP = [NSMutableArray array];
	for (int i = 0; i < 4; i++)
	{
		NSMutableArrayAppendUniqObjectUnsafe(arrayA, @(i));
		NSMutableArrayPrependUniqObjectUnsafe(arrayP, @(i));
	}
	XCTAssert([arrayA count] == 4, @"Append all uniq: Pass");
	XCTAssert([arrayP count] == 4, @"Prepend all uniq: Pass");
	[arrayA removeAllObjects];
	[arrayP removeAllObjects];


	for (int i = 0; i < 4; i++)
	{
		NSMutableArrayAppendUniqObjectUnsafe(arrayA, @(i));
		NSMutableArrayAppendUniqObjectUnsafe(arrayA, @(i - 1));

		NSMutableArrayPrependUniqObjectUnsafe(arrayP, @(i));
		NSMutableArrayPrependUniqObjectUnsafe(arrayP, @(i - 1));
	}
	// 5 with '-1' value
	XCTAssert([arrayA count] == 5, @"Append uniq and prev uniq: Pass");
	XCTAssert([arrayP count] == 5, @"Prepend uniq and prev uniq: Pass");
	[arrayA removeAllObjects];
	[arrayP removeAllObjects];


	XCTAssert(YES, @"Pass");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end

