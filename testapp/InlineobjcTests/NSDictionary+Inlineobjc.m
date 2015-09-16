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
#import "NSDictionary+Inlineobjc.h"

@interface NSDictionary_Inlineobjc : XCTestCase

@end

@implementation NSDictionary_Inlineobjc

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
	NSDictionary * src = @{ @"key1" : @"value",
							@"key2" : @(1),
							@"key3" : @(YES),
							@"key4" : @(NO),
							@"key5" : @[ @"value1", @"value2", @(5) ],
							@"key6" : @{ @"key1" : @(5) }
							};

	// This is an example of a functional test case.
	XCTAssert(NSDictionaryGetPropertyListData(nil) == nil, @"ERROR NSDictionaryGetPropertyListData");
	XCTAssert(NSDictionaryGetPropertyListData(@{}) != nil, @"ERROR NSDictionaryGetPropertyListData");
	XCTAssert(NSDictionaryGetPropertyListData(src) != nil, @"ERROR NSDictionaryGetPropertyListData");


	XCTAssert(NSDictionaryGetBinaryPropertyListData(nil) == nil, @"ERROR NSDictionaryGetBinaryPropertyListData");
	XCTAssert(NSDictionaryGetBinaryPropertyListData(@{}) != nil, @"ERROR NSDictionaryGetBinaryPropertyListData");
	XCTAssert(NSDictionaryGetBinaryPropertyListData(src) != nil, @"ERROR NSDictionaryGetBinaryPropertyListData");

	NSData * data = NSDictionaryGetPropertyListData(src);
	NSDictionary * dst1 = NSDictionaryCreateWithPropertyListData(data);
	XCTAssert([dst1 isEqualToDictionary:src], @"ERROR NSDictionaryGetPropertyListData >> NSDictionaryCreateWithPropertyListData");


	data = NSDictionaryGetBinaryPropertyListData(src);
	dst1 = NSDictionaryCreateWithPropertyListData(data);
	XCTAssert([dst1 isEqualToDictionary:src], @"ERROR NSDictionaryGetBinaryPropertyListData >> NSDictionaryCreateWithPropertyListData");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end
