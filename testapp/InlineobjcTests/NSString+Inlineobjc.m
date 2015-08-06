//
//  InlineobjcTests.m
//  InlineobjcTests
//
//  Created by Resident evil on 7/31/15.
//  Copyright (c) 2015 Resident evil. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "NSString+Inlineobjc.h"

@interface NSString_Inlineobjc : XCTestCase

@end

@implementation NSString_Inlineobjc

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
	XCTAssert(NSStringIsEmpty(nil), @"ERROR NSStringIsEmpty");
	XCTAssert(NSStringIsEmpty(@""), @"ERROR NSStringIsEmpty");
	XCTAssert(!NSStringIsEmpty(@"a"), @"ERROR NSStringIsEmpty");

	XCTAssert(NSStringIsNotEmpty(@"a"), @"ERROR NSStringIsNotEmpty");
	XCTAssert(!NSStringIsNotEmpty(nil), @"ERROR NSStringIsNotEmpty");
	XCTAssert(!NSStringIsNotEmpty(@""), @"ERROR NSStringIsNotEmpty");

	XCTAssert(NSStringIsContainesSubstring(@"This is an example", @"This"), @"ERROR NSStringIsContainesSubstring");
	XCTAssert(NSStringIsContainesSubstring(@"This is an example", @"THIS"), @"ERROR NSStringIsContainesSubstring");
	XCTAssert(NSStringIsContainesSubstring(@"This is an example", @"this"), @"ERROR NSStringIsContainesSubstring");

	XCTAssert(!NSStringIsContainesSubstring(nil, nil), @"ERROR NSStringIsContainesSubstring");
	XCTAssert(!NSStringIsContainesSubstring(@"", @""), @"ERROR NSStringIsContainesSubstring");
	XCTAssert(!NSStringIsContainesSubstring(@"This is an example", nil), @"ERROR NSStringIsContainesSubstring");
	XCTAssert(!NSStringIsContainesSubstring(@"This is an example", @""), @"ERROR NSStringIsContainesSubstring");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end
