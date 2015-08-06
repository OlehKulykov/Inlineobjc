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
 @brief Return number of objects.
 @param array An array for test.
 @return Number of objects or 0 on nil array.
 */
NS_INLINE NSUInteger NSArrayCount(NSArray * array)
{
#if defined(DEBUG)
	if (array)
	{
		assert([array isKindOfClass:[NSArray class]]);
	}
#endif
	return (array) ? [array count] : 0;
}


/**
 @brief Check is array has no objects or nil.
 @param array An array for test.
 @return YES if no objects or nil, othervice NO.
 */
NS_INLINE BOOL NSArrayIsEmpty(NSArray * array)
{
#if defined(DEBUG)
	if (array)
	{
		assert([array isKindOfClass:[NSArray class]]);
	}
#endif
	return (array) ? ([array count] == 0) : YES;
}


/**
 @brief Check is array has objects and not nil.
 @param array An array for test.
 @return YES if not nil and have objects, othervice NO.
 */
NS_INLINE BOOL NSArrayIsNotEmpty(NSArray * array)
{
#if defined(DEBUG)
	if (array)
	{
		assert([array isKindOfClass:[NSArray class]]);
	}
#endif
	return (array) ? ([array count] > 0) : NO;
}


/**
 @brief Get array object at index.
 @param array The target array.
 @param index Index of required object.
 @return Object or nil if array empty or index dosn't exists.
 */
NS_INLINE id NSArrayObjectAtIndex(NSArray * array, const NSUInteger index)
{
#if defined(DEBUG)
	if (array)
	{
		assert([array isKindOfClass:[NSArray class]]);
	}
#endif
	const NSUInteger count = array ? [array count] : 0;
	return (index < count) ? [array objectAtIndex:index] : nil;
}

