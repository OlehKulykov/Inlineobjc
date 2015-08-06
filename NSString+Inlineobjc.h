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


#import <Foundation/Foundation.h>

#if defined(DEBUG) || defined(_DEBUG)
#ifndef DEBUG
#define DEBUG 1
#endif
#endif


/**
 @brief Check string is empty.
 @param stringToTest The test string object.
 @return YES if nil or length is 0, othervice NO.
 */
NS_INLINE BOOL NSStringIsEmpty(NSString * stringToTest)
{
#if defined(DEBUG)
	if (stringToTest)
	{
		assert([stringToTest isKindOfClass:[NSString class]]);
	}
#endif
	return (stringToTest) ? ([stringToTest length] == 0) : YES;
}


/**
 @brief Check string is not empty.
 @param stringToTest The test string object.
 @return YES string has character and not nil, othervice NO.
 */
NS_INLINE BOOL NSStringIsNotEmpty(NSString * stringToTest)
{
#if defined(DEBUG)
	if (stringToTest)
	{
		assert([stringToTest isKindOfClass:[NSString class]]);
	}
#endif
	return (stringToTest) ? ([stringToTest length] > 0) : NO;
}


/**
 @brief Check file path exists.
 @param pathForTest The test path string object.
 @return YES path exists and not directory, othervice NO.
 */
NS_INLINE BOOL NSStringIsFilePathExists(NSString * pathForTest)
{
	if (NSStringIsNotEmpty(pathForTest)) 
	{
		BOOL isDir = YES;
		if ([[NSFileManager defaultManager] fileExistsAtPath:pathForTest isDirectory:&isDir]) 
		{
			return ( !isDir );
		}
	}
	return NO;
}


/**
 @brief Check directory path exists.
 @param pathForTest The test path string object.
 @return YES path exists and is directory, othervice NO.
 */
NS_INLINE BOOL NSStringIsDirPathExists(NSString * pathForTest)
{
	if (NSStringIsNotEmpty(pathForTest)) 
	{
		BOOL isDir = NO;
		if ([[NSFileManager defaultManager] fileExistsAtPath:pathForTest isDirectory:&isDir]) 
		{
			return isDir;
		}
	}
	return NO;
}


/**
 @brief Check string containes not empty substring using case insensitive search.
 @param subString The string object for searching.
 @return YES substring conteines, othervice NO.
 */
NS_INLINE BOOL NSStringIsContainesSubstring(NSString * sourceString, NSString * subString)
{
	if (sourceString && subString)
	{
#if defined(DEBUG)
		assert([sourceString isKindOfClass:[NSString class]]);
		assert([subString isKindOfClass:[NSString class]]);
#endif
		const NSRange r = [sourceString rangeOfString:subString options:NSCaseInsensitiveSearch];
		return (r.location != NSNotFound && r.length != 0);
	}
	return NO;
}

