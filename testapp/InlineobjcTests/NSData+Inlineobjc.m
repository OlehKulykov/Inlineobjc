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
#import "NSData+Inlineobjc.h"

@interface NSData_Inlineobjc : XCTestCase

@end

@implementation NSData_Inlineobjc

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

	NSString * srcString = @"Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
	srcString = [srcString stringByAppendingString:@"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."];

	NSData * src1 = [NSData dataWithBytes:[srcString UTF8String] length:[srcString lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
	XCTAssert(src1 != nil, @"ERROR internal");

	NSData * dst1 = NSDataGetZipCompressDataWithRatio(src1, 1);
	XCTAssert(dst1 != nil, @"ERROR NSDataGetZipCompressDataWithRatio");

	NSData * dst2 = NSDataGetZipDecompressData(dst1);
	XCTAssert(dst2 != nil, @"ERROR NSDataGetZipDecompressData");

	XCTAssert([src1 isEqualToData:dst2], @"ERROR NSDataGetZipDecompressData");






	srcString = @"Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
	srcString = [srcString stringByAppendingString:@"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."];

	src1 = [NSData dataWithBytes:[srcString UTF8String] length:[srcString lengthOfBytesUsingEncoding:NSUTF8StringEncoding]];
	XCTAssert(src1 != nil, @"ERROR internal");

	dst1 = NSDataGetLzmaCompressDataWithRatio(src1, 1);
	XCTAssert(dst1 != nil, @"ERROR NSDataGetLzmaCompressDataWithRatio");

	dst2 = NSDataGetLzmaDecompressData(dst1);
	XCTAssert(dst2 != nil, @"ERROR NSDataGetLzmaDecompressData");

	XCTAssert([src1 isEqualToData:dst2], @"ERROR NSDataGetLzmaDecompressData");
}

- (void)testPerformanceExample
{
	// This is an example of a performance test case.
	[self measureBlock:^{
		// Put the code you want to measure the time of here.
	}];
}

@end
