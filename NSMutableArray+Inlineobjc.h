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

NS_INLINE void NSMutableArrayAppendUniqObjectUnsafe(NSMutableArray * array, id object)
{
#if defined(DEBUG)
	assert(array != nil);
	assert(object != nil);
#endif
	if (![array containsObject:object]) [array addObject:object];
}

NS_INLINE void NSMutableArrayPrependUniqObjectUnsafe(NSMutableArray * array, id object)
{
#if defined(DEBUG)
	assert(array != nil);
	assert(object != nil);
#endif
	if (![array containsObject:object]) [array insertObject:object atIndex:0];
}

NS_INLINE void NSMutableArrayAppendUniqObjectSafe(NSMutableArray * array, id object)
{
	if (array && object)
	{
#if defined(DEBUG)
		assert([array isKindOfClass:[NSMutableArray class]]);
#endif
		NSMutableArrayAppendUniqObjectUnsafe(array, object);
	}
}

NS_INLINE void NSMutableArrayAppendUniqSafe(NSMutableArray * array, id<NSFastEnumeration> from)
{
	if (array && from)
	{
#if defined(DEBUG)
		assert([array isKindOfClass:[NSMutableArray class]]);
#endif
		for (id object in from)
		{
			NSMutableArrayAppendUniqObjectUnsafe(array, object);
		}
	}
}

NS_INLINE void NSMutableArrayPrependUniqObjectSafe(NSMutableArray * array, id object)
{
	if (array && object)
	{
#if defined(DEBUG)
		assert([array isKindOfClass:[NSMutableArray class]]);
#endif
		NSMutableArrayPrependUniqObjectUnsafe(array, object);
	}
}

NS_INLINE void NSMutableArrayPrependUniqSafe(NSMutableArray * array, id<NSFastEnumeration> from)
{
	if (array && from)
	{
#if defined(DEBUG)
		assert([array isKindOfClass:[NSMutableArray class]]);
#endif
		for (id object in from)
		{
			NSMutableArrayPrependUniqObjectUnsafe(array, object);
		}
	}
}

