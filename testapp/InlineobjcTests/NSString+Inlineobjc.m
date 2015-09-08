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

	XCTAssert(NSStringsAreEqual(@"", @""), @"ERROR NSStringsAreEqual");
	XCTAssert(NSStringsAreEqual(@"a", @"a"), @"ERROR NSStringsAreEqual");
	XCTAssert(!NSStringsAreEqual(@"a", @"b"), @"ERROR NSStringsAreEqual");
	XCTAssert(!NSStringsAreEqual(@"", @"a"), @"ERROR NSStringsAreEqual");
	XCTAssert(!NSStringsAreEqual(@"", nil), @"ERROR NSStringsAreEqual");
	XCTAssert(!NSStringsAreEqual(nil, @""), @"ERROR NSStringsAreEqual");


	XCTAssert(!NSStringIsUppercase(nil), @"ERROR NSStringIsUppercase");
	XCTAssert(!NSStringIsUppercase(@""), @"ERROR NSStringIsUppercase");
	XCTAssert(NSStringIsUppercase(@"ABR"), @"ERROR NSStringIsUppercase");
	XCTAssert(NSStringIsUppercase(@"АБР"), @"ERROR NSStringIsUppercase");
	XCTAssert(!NSStringIsUppercase(@"AbR"), @"ERROR NSStringIsUppercase");
	XCTAssert(!NSStringIsUppercase(@"АРвф"), @"ERROR NSStringIsUppercase");
	XCTAssert(NSStringIsUppercase(@"MÜN"), @"ERROR NSStringIsUppercase");
	XCTAssert(!NSStringIsUppercase(@"MüN"), @"ERROR NSStringIsUppercase");


	XCTAssert(!NSStringIsLowercase(nil), @"ERROR NSStringIsLowercase");
	XCTAssert(!NSStringIsLowercase(@""), @"ERROR NSStringIsLowercase");
	XCTAssert(NSStringIsLowercase(@"abr"), @"ERROR NSStringIsLowercase");
	XCTAssert(NSStringIsLowercase(@"абр"), @"ERROR NSStringIsLowercase");
	XCTAssert(!NSStringIsLowercase(@"aBr"), @"ERROR NSStringIsLowercase");
	XCTAssert(!NSStringIsLowercase(@"абвФ"), @"ERROR NSStringIsLowercase");
	XCTAssert(NSStringIsLowercase(@"mün"), @"ERROR NSStringIsLowercase");
	XCTAssert(!NSStringIsLowercase(@"mÜn"), @"ERROR NSStringIsLowercase");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end
