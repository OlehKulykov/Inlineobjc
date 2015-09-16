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

#define LZMA_PROPS_SIZE 5
#define kMaxHistorySize ((uint32_t)3 << 29)

#define kBlockSizeMax ((1 << LZMA_NUM_BLOCK_SIZE_BITS) - 1)

#define kBlockSize (9 << 10)
#define kUnpackBlockSize (1 << 18)
#define kMatchArraySize (1 << 21)
#define kMatchRecordMaxSize ((LZMA_MATCH_LEN_MAX * 2 + 3) * LZMA_MATCH_LEN_MAX)
#define kNumMaxDirectBits (31)
#define kNumTopBits 24
#define kTopValue ((uint32_t)1 << kNumTopBits)
#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5
#define kProbInitValue (kBitModelTotal >> 1)
#define kNumMoveReducingBits 4
#define kNumBitPriceShiftBits 4
#define kBitPrice (1 << kNumBitPriceShiftBits)
#define LZMA_NUM_REPS 4
#define kNumOpts (1 << 12)

#define kNumLenToPosStates 4
#define kNumPosSlotBits 6
#define kDicLogSizeMin 0
#define kDicLogSizeMax 32
#define kDistTableSizeMax (kDicLogSizeMax * 2)
#define kNumAlignBits 4
#define kAlignTableSize (1 << kNumAlignBits)
#define kAlignMask (kAlignTableSize - 1)
#define kStartPosModelIndex 4
#define kEndPosModelIndex 14
#define kNumPosModels (kEndPosModelIndex - kStartPosModelIndex)
#define kNumFullDistances (1 << (kEndPosModelIndex >> 1))
#define LZMA_MATCH_LEN_MIN 2
#define LZMA_MATCH_LEN_MAX (LZMA_MATCH_LEN_MIN + kLenNumSymbolsTotal - 1)
#define kLenNumLowBits 3
#define kLenNumLowSymbols (1 << kLenNumLowBits)
#define kLenNumMidBits 3
#define kLenNumMidSymbols (1 << kLenNumMidBits)
#define kLenNumHighBits 8
#define kLenNumHighSymbols (1 << kLenNumHighBits)
#define kLenNumSymbolsTotal (kLenNumLowSymbols + kLenNumMidSymbols + kLenNumHighSymbols)
#define kNumStates 12
#define LZMA_PB_MAX 4
#define LZMA_LC_MAX 8
#define LZMA_LP_MAX 4
#define LZMA_NUM_PB_STATES_MAX (1 << LZMA_PB_MAX)
#define kDicLogSizeMaxCompress 32

#define SZ_OK 0
#define SZ_ERROR_DATA 1
#define SZ_ERROR_MEM 2
#define SZ_ERROR_CRC 3
#define SZ_ERROR_UNSUPPORTED 4
#define SZ_ERROR_PARAM 5
#define SZ_ERROR_INPUT_EOF 6
#define SZ_ERROR_OUTPUT_EOF 7
#define SZ_ERROR_READ 8
#define SZ_ERROR_WRITE 9
#define SZ_ERROR_PROGRESS 10
#define SZ_ERROR_FAIL 11
#define SZ_ERROR_THREAD 12
#define SZ_ERROR_ARCHIVE 16
#define SZ_ERROR_NO_ARCHIVE 17
#define RINOK(x) { int __result__ = (x); if (__result__ != 0) return __result__; }
#define kHash2Size (1 << 10)
#define kHash3Size (1 << 16)
#define kHash4Size (1 << 20)

#define kFix3HashSize (kHash2Size)
#define kFix4HashSize (kHash2Size + kHash3Size)
#define kFix5HashSize (kHash2Size + kHash3Size + kHash4Size)

#define HASH2_CALC hv = cur[0] | ((uint32_t)cur[1] << 8);

#define HASH3_CALC { \
uint32_t temp = p->crc[cur[0]] ^ cur[1]; \
h2 = temp & (kHash2Size - 1); \
hv = (temp ^ ((uint32_t)cur[2] << 8)) & p->hashMask; }

#define HASH4_CALC { \
uint32_t temp = p->crc[cur[0]] ^ cur[1]; \
h2 = temp & (kHash2Size - 1); \
temp ^= ((uint32_t)cur[2] << 8); \
h3 = temp & (kHash3Size - 1); \
hv = (temp ^ (p->crc[cur[3]] << 5)) & p->hashMask; }

#define HASH5_CALC { \
uint32_t temp = p->crc[cur[0]] ^ cur[1]; \
h2 = temp & (kHash2Size - 1); \
temp ^= ((uint32_t)cur[2] << 8); \
h3 = temp & (kHash3Size - 1); \
temp ^= (p->crc[cur[3]] << 5); \
h4 = temp & (kHash4Size - 1); \
hv = (temp ^ (p->crc[cur[4]] << 3)) & p->hashMask; }

#define HASH_ZIP_CALC hv = ((cur[2] | ((uint32_t)cur[0] << 8)) ^ p->crc[cur[1]]) & 0xFFFF;

#define MT_HASH2_CALC \
h2 = (p->crc[cur[0]] ^ cur[1]) & (kHash2Size - 1);

#define MT_HASH3_CALC { \
uint32_t temp = p->crc[cur[0]] ^ cur[1]; \
h2 = temp & (kHash2Size - 1); \
h3 = (temp ^ ((uint32_t)cur[2] << 8)) & (kHash3Size - 1); }

#define MT_HASH4_CALC { \
uint32_t temp = p->crc[cur[0]] ^ cur[1]; \
h2 = temp & (kHash2Size - 1); \
temp ^= ((uint32_t)cur[2] << 8); \
h3 = temp & (kHash3Size - 1); \
h4 = (temp ^ (p->crc[cur[3]] << 5)) & (kHash4Size - 1); }

#define kEmptyHashValue 0
#define kMaxValForNormalize ((uint32_t)0xFFFFFFFF)
#define kNormalizeStepMin (1 << 10)
#define kNormalizeMask (~(kNormalizeStepMin - 1))

typedef struct _CLzmaEncProps
{
	int level;       /*  0 <= level <= 9 */
	uint32_t dictSize; /* (1 << 12) <= dictSize <= (1 << 27) for 32-bit version
						(1 << 12) <= dictSize <= (1 << 30) for 64-bit version
						default = (1 << 24) */
	uint64_t reduceSize; /* estimated size of data that will be compressed. default = 0xFFFFFFFF.
						  Encoder uses this value to reduce dictionary size */
	int lc;          /* 0 <= lc <= 8, default = 3 */
	int lp;          /* 0 <= lp <= 4, default = 0 */
	int pb;          /* 0 <= pb <= 4, default = 2 */
	int algo;        /* 0 - fast, 1 - normal, default = 1 */
	int fb;          /* 5 <= fb <= 273, default = 32 */
	int btMode;      /* 0 - hashChain Mode, 1 - binTree mode - normal, default = 1 */
	int numHashBytes; /* 2, 3 or 4, default = 4 */
	uint32_t mc;        /* 1 <= mc <= (1 << 30), default = 32 */
	unsigned writeEndMark;  /* 0 - do not write EOPM, 1 - write EOPM, default = 0 */
	int numThreads;  /* 1 or 2, default = 2 */
} CLzmaEncProps;

static void LzmaEncProps_Init(CLzmaEncProps *p) {
	p->level = 5;
	p->dictSize = p->mc = 0;
	p->reduceSize = (uint64_t)(int64_t)-1;
	p->lc = p->lp = p->pb = p->algo = p->fb = p->btMode = p->numHashBytes = p->numThreads = -1;
	p->writeEndMark = 0;
}

typedef struct {
	int (*Progress)(void *p, uint64_t inSize, uint64_t outSize);
} ICompressProgress;

typedef void (*Mf_Init_Func)(void *object);
typedef uint32_t (*Mf_GetNumAvailableBytes_Func)(void *object);
typedef const uint8_t * (*Mf_GetPointerToCurrentPos_Func)(void *object);
typedef uint32_t (*Mf_GetMatches_Func)(void *object, uint32_t *distances);
typedef void (*Mf_Skip_Func)(void *object, uint32_t);

typedef struct _IMatchFinder {
	Mf_Init_Func Init;
	Mf_GetNumAvailableBytes_Func GetNumAvailableBytes;
	Mf_GetPointerToCurrentPos_Func GetPointerToCurrentPos;
	Mf_GetMatches_Func GetMatches;
	Mf_Skip_Func Skip;
} IMatchFinder;

typedef struct {
	size_t (*Write)(void *p, const void *buf, size_t size);
} ISeqOutStream;

typedef struct {
	uint32_t range;
	uint8_t cache;
	uint64_t low;
	uint64_t cacheSize;
	uint8_t *buf;
	uint8_t *bufLim;
	uint8_t *bufBase;
	ISeqOutStream *outStream;
	uint64_t processed;
	int res;
} CRangeEnc;

typedef uint32_t CLzRef;

typedef struct {
	int (*Read)(void *p, void *buf, size_t *size);
} ISeqInStream;

typedef struct _CMatchFinder {
	uint8_t *buffer;
	uint32_t pos;
	uint32_t posLimit;
	uint32_t streamPos;
	uint32_t lenLimit;
	uint32_t cyclicBufferPos;
	uint32_t cyclicBufferSize; /* it must be = (historySize + 1) */

	uint8_t streamEndWasReached;
	uint8_t btMode;
	uint8_t bigHash;
	uint8_t directInput;

	uint32_t matchMaxLen;
	CLzRef *hash;
	CLzRef *son;
	uint32_t hashMask;
	uint32_t cutValue;

	uint8_t *bufferBase;
	ISeqInStream *stream;

	uint32_t blockSize;
	uint32_t keepSizeBefore;
	uint32_t keepSizeAfter;
	uint32_t numHashBytes;
	size_t directInputRem;
	uint32_t historySize;
	uint32_t fixedHashSize;
	uint32_t hashSizeSum;
	int result;
	uint32_t crc[256];
	size_t numRefs;
} CMatchFinder;

typedef unsigned CState;

typedef struct {
	CState state;
	uint32_t price;
	uint32_t posPrev2;
	uint32_t backPrev2;
	uint32_t posPrev;
	uint32_t backPrev;
	uint32_t backs[LZMA_NUM_REPS];
	int prev1IsChar;
	int prev2;
} COptimal;

typedef struct {
	uint16_t choice;
	uint16_t choice2;
	uint16_t low[LZMA_NUM_PB_STATES_MAX << kLenNumLowBits];
	uint16_t mid[LZMA_NUM_PB_STATES_MAX << kLenNumMidBits];
	uint16_t high[kLenNumHighSymbols];
} CLenEnc;

typedef struct {
	CLenEnc p;
	uint32_t tableSize;
	uint32_t prices[LZMA_NUM_PB_STATES_MAX][kLenNumSymbolsTotal];
	uint32_t counters[LZMA_NUM_PB_STATES_MAX];
} CLenPriceEnc;

typedef struct {
	uint16_t *litProbs;

	uint32_t state;
	uint32_t reps[LZMA_NUM_REPS];

	uint16_t isMatch[kNumStates][LZMA_NUM_PB_STATES_MAX];
	uint16_t isRep[kNumStates];
	uint16_t isRepG0[kNumStates];
	uint16_t isRepG1[kNumStates];
	uint16_t isRepG2[kNumStates];
	uint16_t isRep0Long[kNumStates][LZMA_NUM_PB_STATES_MAX];
	uint16_t posSlotEncoder[kNumLenToPosStates][1 << kNumPosSlotBits];
	uint16_t posEncoders[kNumFullDistances - kEndPosModelIndex];
	uint16_t posAlignEncoder[1 << kNumAlignBits];

	CLenPriceEnc lenEnc;
	CLenPriceEnc repLenEnc;
} CSaveState;

typedef struct {
	void *matchFinderObj;
	IMatchFinder matchFinder;

	uint32_t optimumEndIndex;
	uint32_t optimumCurrentIndex;
	uint32_t longestMatchLength;
	uint32_t numPairs;
	uint32_t numAvail;
	uint32_t numFastBytes;
	uint32_t additionalOffset;
	uint32_t reps[LZMA_NUM_REPS];
	uint32_t state;

	unsigned lc, lp, pb;
	unsigned lpMask, pbMask;
	unsigned lclp;

	uint16_t *litProbs;

	uint8_t fastMode;
	uint8_t writeEndMark;
	uint8_t finished;
	uint8_t multiThread;
	uint8_t needInit;

	uint64_t nowPos64;

	uint32_t matchPriceCount;
	uint32_t alignPriceCount;
	uint32_t distTableSize;
	uint32_t dictSize;
	int result;

	CRangeEnc rc;
	CMatchFinder matchFinderBase;
	COptimal opt[kNumOpts];

	uint32_t ProbPrices[kBitModelTotal >> kNumMoveReducingBits];
	uint32_t matches[LZMA_MATCH_LEN_MAX * 2 + 2 + 1];
	uint32_t posSlotPrices[kNumLenToPosStates][kDistTableSizeMax];
	uint32_t distancesPrices[kNumLenToPosStates][kNumFullDistances];
	uint32_t alignPrices[kAlignTableSize];
	uint16_t isMatch[kNumStates][LZMA_NUM_PB_STATES_MAX];
	uint16_t isRep[kNumStates];
	uint16_t isRepG0[kNumStates];
	uint16_t isRepG1[kNumStates];
	uint16_t isRepG2[kNumStates];
	uint16_t isRep0Long[kNumStates][LZMA_NUM_PB_STATES_MAX];
	uint16_t posSlotEncoder[kNumLenToPosStates][1 << kNumPosSlotBits];
	uint16_t posEncoders[kNumFullDistances - kEndPosModelIndex];
	uint16_t posAlignEncoder[1 << kNumAlignBits];

	CLenPriceEnc lenEnc;
	CLenPriceEnc repLenEnc;
	CSaveState saveState;
} CLzmaEnc;

typedef struct {
	void *(*Alloc)(void *p, size_t size);
	void (*Free)(void *p, void *address); /* address can be 0 */
} ISzAlloc;

typedef void * CLzmaEncHandle;

static void RangeEnc_Construct(CRangeEnc *p) {
	p->outStream = 0;
	p->bufBase = 0;
}

#define kCrcPoly 0xEDB88320

static void MatchFinder_SetDefaultSettings(CMatchFinder *p) {
	p->cutValue = 32;
	p->btMode = 1;
	p->numHashBytes = 4;
	p->bigHash = 0;
}

static void MatchFinder_Construct(CMatchFinder *p) {
	uint32_t i;
	p->bufferBase = NULL;
	p->directInput = 0;
	p->hash = NULL;
	MatchFinder_SetDefaultSettings(p);

	for (i = 0; i < 256; i++)
	{
		uint32_t r = i;
		unsigned j;
		for (j = 0; j < 8; j++)
			r = (r >> 1) ^ (kCrcPoly & ~((r & 1) - 1));
		p->crc[i] = r;
	}
}

static void LzmaEncProps_Normalize(CLzmaEncProps *p) {
	int level = p->level;
	if (level < 0) level = 5;
	p->level = level;

	if (p->dictSize == 0) p->dictSize = (level <= 5 ? (1 << (level * 2 + 14)) : (level == 6 ? (1 << 25) : (1 << 26)));
	if (p->dictSize > p->reduceSize)
	{
		unsigned i;
		for (i = 11; i <= 30; i++)
		{
			if ((uint32_t)p->reduceSize <= ((uint32_t)2 << i)) { p->dictSize = ((uint32_t)2 << i); break; }
			if ((uint32_t)p->reduceSize <= ((uint32_t)3 << i)) { p->dictSize = ((uint32_t)3 << i); break; }
		}
	}

	if (p->lc < 0) p->lc = 3;
	if (p->lp < 0) p->lp = 0;
	if (p->pb < 0) p->pb = 2;
	if (p->algo < 0) p->algo = (level < 5 ? 0 : 1);
	if (p->fb < 0) p->fb = (level < 7 ? 32 : 64);
	if (p->btMode < 0) p->btMode = (p->algo == 0 ? 0 : 1);
	if (p->numHashBytes < 0) p->numHashBytes = 4;
	if (p->mc == 0) p->mc = (16 + (p->fb >> 1)) >> (p->btMode ? 0 : 1);
	if (p->numThreads < 0) p->numThreads = 1;
}

static int LzmaEnc_SetProps(CLzmaEncHandle pp, const CLzmaEncProps *props2) {
	CLzmaEnc *p = (CLzmaEnc *)pp;
	CLzmaEncProps props = *props2;
	LzmaEncProps_Normalize(&props);

	if (props.lc > LZMA_LC_MAX
		|| props.lp > LZMA_LP_MAX
		|| props.pb > LZMA_PB_MAX
		|| props.dictSize > ((uint64_t)1 << kDicLogSizeMaxCompress)
		|| props.dictSize > kMaxHistorySize)
		return SZ_ERROR_PARAM;

	p->dictSize = props.dictSize;
	{
		unsigned fb = props.fb;
		if (fb < 5)
			fb = 5;
		if (fb > LZMA_MATCH_LEN_MAX)
			fb = LZMA_MATCH_LEN_MAX;
		p->numFastBytes = fb;
	}
	p->lc = props.lc;
	p->lp = props.lp;
	p->pb = props.pb;
	p->fastMode = (props.algo == 0);
	p->matchFinderBase.btMode = (uint8_t)(props.btMode ? 1 : 0);
	{
		uint32_t numHashBytes = 4;
		if (props.btMode)
		{
			if (props.numHashBytes < 2)
				numHashBytes = 2;
			else if (props.numHashBytes < 4)
				numHashBytes = props.numHashBytes;
		}
		p->matchFinderBase.numHashBytes = numHashBytes;
	}

	p->matchFinderBase.cutValue = props.mc;
	p->writeEndMark = props.writeEndMark;
	return SZ_OK;
}

static void LzmaEnc_InitPriceTables(uint32_t *ProbPrices) {
	for (uint32_t i = (1 << kNumMoveReducingBits) / 2; i < kBitModelTotal; i += (1 << kNumMoveReducingBits))
	{
		const int kCyclesBits = kNumBitPriceShiftBits;
		uint32_t w = i;
		uint32_t bitCount = 0;
		int j;
		for (j = 0; j < kCyclesBits; j++)
		{
			w = w * w;
			bitCount <<= 1;
			while (w >= ((uint32_t)1 << 16))
			{
				w >>= 1;
				bitCount++;
			}
		}
		ProbPrices[i >> kNumMoveReducingBits] = ((kNumBitModelTotalBits << kCyclesBits) - 15 - bitCount);
	}
}

static void LzmaEnc_Construct(CLzmaEnc *p) {
	RangeEnc_Construct(&p->rc);
	MatchFinder_Construct(&p->matchFinderBase);
	{
		CLzmaEncProps props;
		LzmaEncProps_Init(&props);
		LzmaEnc_SetProps(p, &props);
	}

	LzmaEnc_InitPriceTables(p->ProbPrices);
	p->litProbs = 0;
	p->saveState.litProbs = 0;
}

static CLzmaEncHandle LzmaEnc_Create(ISzAlloc *alloc) {
	void * p = alloc->Alloc(alloc, sizeof(CLzmaEnc));
	if (p != 0) LzmaEnc_Construct((CLzmaEnc *)p);
	return p;
}

static int LzmaEnc_WriteProperties(CLzmaEncHandle pp, uint8_t *props, size_t *size) {
	CLzmaEnc *p = (CLzmaEnc *)pp;
	unsigned i;
	uint32_t dictSize = p->dictSize;
	if (*size < LZMA_PROPS_SIZE) return SZ_ERROR_PARAM;
	*size = LZMA_PROPS_SIZE;
	props[0] = (uint8_t)((p->pb * 5 + p->lp) * 9 + p->lc);

	if (dictSize >= ((uint32_t)1 << 22))
	{
		uint32_t kDictMask = ((uint32_t)1 << 20) - 1;
		if (dictSize < (uint32_t)0xFFFFFFFF - kDictMask)
			dictSize = (dictSize + kDictMask) & ~kDictMask;
	}
	else for (i = 11; i <= 30; i++)
	{
		if (dictSize <= ((uint32_t)2 << i)) { dictSize = (2 << i); break; }
		if (dictSize <= ((uint32_t)3 << i)) { dictSize = (3 << i); break; }
	}

	for (i = 0; i < 4; i++)
		props[1 + i] = (uint8_t)(dictSize >> (8 * i));
	return SZ_OK;
}

typedef struct {
	ISeqOutStream funcTable;
	uint8_t *data;
	size_t rem;
	uint8_t overflow;
} CSeqOutStreamBuf;

static void LzmaEnc_SetInputBuf(CLzmaEnc *p, const uint8_t *src, size_t srcLen) {
	p->matchFinderBase.directInput = 1;
	p->matchFinderBase.bufferBase = (uint8_t *)src;
	p->matchFinderBase.directInputRem = srcLen;
}

static size_t MyWrite(void *pp, const void *data, size_t size) {
	CSeqOutStreamBuf *p = (CSeqOutStreamBuf *)pp;
	if (p->rem < size)
	{
		size = p->rem;
		p->overflow = 1;
	}
	memcpy(p->data, data, size);
	p->rem -= size;
	p->data += size;
	return size;
}

#define kBigHashDicLimit ((uint32_t)1 << 24)
#define RangeEnc_GetProcessed(p) ((p)->processed + ((p)->buf - (p)->bufBase) + (p)->cacheSize)
#define RC_BUF_SIZE (1 << 16)

static int RangeEnc_Alloc(CRangeEnc *p, ISzAlloc *alloc) {
	if (p->bufBase == 0)
	{
		p->bufBase = (uint8_t *)alloc->Alloc(alloc, RC_BUF_SIZE);
		if (p->bufBase == 0) return 0;
		p->bufLim = p->bufBase + RC_BUF_SIZE;
	}
	return 1;
}

static void RangeEnc_Free(CRangeEnc *p, ISzAlloc *alloc) {
	alloc->Free(alloc, p->bufBase);
	p->bufBase = 0;
}

static void LzmaEnc_FreeLits(CLzmaEnc *p, ISzAlloc *alloc) {
	alloc->Free(alloc, p->litProbs);
	alloc->Free(alloc, p->saveState.litProbs);
	p->litProbs = 0;
	p->saveState.litProbs = 0;
}

static void MatchFinder_FreeThisClassMemory(CMatchFinder *p, ISzAlloc *alloc) {
	alloc->Free(alloc, p->hash);
	p->hash = NULL;
}

static void LzInWindow_Free(CMatchFinder *p, ISzAlloc *alloc) {
	if (!p->directInput)
	{
		alloc->Free(alloc, p->bufferBase);
		p->bufferBase = NULL;
	}
}

void MatchFinder_Free(CMatchFinder *p, ISzAlloc *alloc) {
	MatchFinder_FreeThisClassMemory(p, alloc);
	LzInWindow_Free(p, alloc);
}

static int LzInWindow_Create(CMatchFinder *p, uint32_t keepSizeReserv, ISzAlloc *alloc) {
	uint32_t blockSize = p->keepSizeBefore + p->keepSizeAfter + keepSizeReserv;
	if (p->directInput)
	{
		p->blockSize = blockSize;
		return 1;
	}
	if (!p->bufferBase || p->blockSize != blockSize)
	{
		LzInWindow_Free(p, alloc);
		p->blockSize = blockSize;
		p->bufferBase = (uint8_t *)alloc->Alloc(alloc, (size_t)blockSize);
	}
	return (p->bufferBase != NULL);
}

static CLzRef* AllocRefs(size_t num, ISzAlloc *alloc) {
	size_t sizeInBytes = (size_t)num * sizeof(CLzRef);
	if (sizeInBytes / sizeof(CLzRef) != num) return NULL;
	return (CLzRef *)alloc->Alloc(alloc, sizeInBytes);
}

static int MatchFinder_Create(CMatchFinder *p, uint32_t historySize,
							  uint32_t keepAddBufferBefore, uint32_t matchMaxLen, uint32_t keepAddBufferAfter, ISzAlloc *alloc) {
	uint32_t sizeReserv;
	if (historySize > kMaxHistorySize)
	{
		MatchFinder_Free(p, alloc);
		return 0;
	}

	sizeReserv = historySize >> 1;
	if (historySize >= ((uint32_t)3 << 30)) sizeReserv = historySize >> 3;
	else if (historySize >= ((uint32_t)2 << 30)) sizeReserv = historySize >> 2;

	sizeReserv += (keepAddBufferBefore + matchMaxLen + keepAddBufferAfter) / 2 + (1 << 19);

	p->keepSizeBefore = historySize + keepAddBufferBefore + 1;
	p->keepSizeAfter = matchMaxLen + keepAddBufferAfter;

	if (LzInWindow_Create(p, sizeReserv, alloc))
	{
		uint32_t newCyclicBufferSize = historySize + 1;
		uint32_t hs;
		p->matchMaxLen = matchMaxLen;
		{
			p->fixedHashSize = 0;
			if (p->numHashBytes == 2) hs = (1 << 16) - 1;
			else
			{
				hs = historySize - 1;
				hs |= (hs >> 1);
				hs |= (hs >> 2);
				hs |= (hs >> 4);
				hs |= (hs >> 8);
				hs >>= 1;
				hs |= 0xFFFF;
				if (hs > (1 << 24))
				{
					if (p->numHashBytes == 3) hs = (1 << 24) - 1;
					else hs >>= 1;
				}
			}
			p->hashMask = hs;
			hs++;
			if (p->numHashBytes > 2) p->fixedHashSize += kHash2Size;
			if (p->numHashBytes > 3) p->fixedHashSize += kHash3Size;
			if (p->numHashBytes > 4) p->fixedHashSize += kHash4Size;
			hs += p->fixedHashSize;
		}
		{
			size_t newSize;
			size_t numSons;
			p->historySize = historySize;
			p->hashSizeSum = hs;
			p->cyclicBufferSize = newCyclicBufferSize;
			numSons = newCyclicBufferSize;
			if (p->btMode) numSons <<= 1;
			newSize = hs + numSons;
			if (p->hash && p->numRefs == newSize) return 1;
			MatchFinder_FreeThisClassMemory(p, alloc);
			p->numRefs = newSize;
			p->hash = AllocRefs(newSize, alloc);
			if (p->hash)
			{
				p->son = p->hash + p->hashSizeSum;
				return 1;
			}
		}
	}
	MatchFinder_Free(p, alloc);
	return 0;
}

static void MatchFinder_ReadBlock(CMatchFinder *p) {
	if (p->streamEndWasReached || p->result != SZ_OK) return;
	if (p->directInput)
	{
		uint32_t curSize = 0xFFFFFFFF - p->streamPos;
		if (curSize > p->directInputRem)
			curSize = (uint32_t)p->directInputRem;
		p->directInputRem -= curSize;
		p->streamPos += curSize;
		if (p->directInputRem == 0) p->streamEndWasReached = 1;
		return;
	}

	for (;;)
	{
		uint8_t *dest = p->buffer + (p->streamPos - p->pos);
		size_t size = (p->bufferBase + p->blockSize - dest);
		if (size == 0) return;
		p->result = p->stream->Read(p->stream, dest, &size);
		if (p->result != SZ_OK) return;
		if (size == 0)
		{
			p->streamEndWasReached = 1;
			return;
		}
		p->streamPos += (uint32_t)size;
		if (p->streamPos - p->pos > p->keepSizeAfter) return;
	}
}

static void MatchFinder_SetLimits(CMatchFinder *p) {
	uint32_t limit = kMaxValForNormalize - p->pos;
	uint32_t limit2 = p->cyclicBufferSize - p->cyclicBufferPos;
	if (limit2 < limit) limit = limit2;
	limit2 = p->streamPos - p->pos;
	if (limit2 <= p->keepSizeAfter)
	{
		if (limit2 > 0)
			limit2 = 1;
	}
	else limit2 -= p->keepSizeAfter;
	if (limit2 < limit) limit = limit2;
	{
		uint32_t lenLimit = p->streamPos - p->pos;
		if (lenLimit > p->matchMaxLen)
			lenLimit = p->matchMaxLen;
		p->lenLimit = lenLimit;
	}
	p->posLimit = p->pos + limit;
}

static void MatchFinder_Init(CMatchFinder *p) {
	uint32_t *hash = p->hash;
	uint32_t num = p->hashSizeSum;
	for (uint32_t i = 0; i < num; i++) hash[i] = kEmptyHashValue;
	p->cyclicBufferPos = 0;
	p->buffer = p->bufferBase;
	p->pos = p->streamPos = p->cyclicBufferSize;
	p->result = SZ_OK;
	p->streamEndWasReached = 0;
	MatchFinder_ReadBlock(p);
	MatchFinder_SetLimits(p);
}

static uint32_t MatchFinder_GetNumAvailableBytes(CMatchFinder *p) { return p->streamPos - p->pos; }
static uint8_t *MatchFinder_GetPointerToCurrentPos(CMatchFinder *p) { return p->buffer; }
static void MatchFinder_CheckLimits(CMatchFinder *p);

#define MOVE_POS \
++p->cyclicBufferPos; \
p->buffer++; \
if (++p->pos == p->posLimit) MatchFinder_CheckLimits(p);

static void MatchFinder_MovePos(CMatchFinder *p) { MOVE_POS; }

#define GET_MATCHES_HEADER2(minLen, ret_op) \
uint32_t lenLimit; uint32_t hv; const uint8_t *cur; uint32_t curMatch; \
lenLimit = p->lenLimit; { if (lenLimit < minLen) { MatchFinder_MovePos(p); ret_op; }} \
cur = p->buffer;

#define GET_MATCHES_HEADER(minLen) GET_MATCHES_HEADER2(minLen, return 0)

#define UPDATE_maxLen { \
ptrdiff_t diff = (ptrdiff_t)0 - d2; \
const uint8_t *c = cur + maxLen; \
const uint8_t *lim = cur + lenLimit; \
for (; c != lim; c++) if (*(c + diff) != *c) break; \
maxLen = (uint32_t)(c - cur); }

static uint32_t MatchFinder_GetSubValue(CMatchFinder *p) { return (p->pos - p->historySize - 1) & kNormalizeMask; }

static void MatchFinder_Normalize3(uint32_t subValue, CLzRef *items, size_t numItems) {
	for (size_t i = 0; i < numItems; i++) {
		uint32_t value = items[i];
		if (value <= subValue) value = kEmptyHashValue;
		else value -= subValue;
		items[i] = value;
	}
}

static void MatchFinder_ReduceOffsets(CMatchFinder *p, uint32_t subValue) {
	p->posLimit -= subValue;
	p->pos -= subValue;
	p->streamPos -= subValue;
}

static void MatchFinder_Normalize(CMatchFinder *p) {
	uint32_t subValue = MatchFinder_GetSubValue(p);
	MatchFinder_Normalize3(subValue, p->hash, p->numRefs);
	MatchFinder_ReduceOffsets(p, subValue);
}

static int MatchFinder_NeedMove(CMatchFinder *p) {
	if (p->directInput) return 0;
	return ((size_t)(p->bufferBase + p->blockSize - p->buffer) <= p->keepSizeAfter);
}

static void MatchFinder_MoveBlock(CMatchFinder *p) {
	memmove(p->bufferBase,
			p->buffer - p->keepSizeBefore,
			(size_t)(p->streamPos - p->pos + p->keepSizeBefore));
	p->buffer = p->bufferBase + p->keepSizeBefore;
}

static void MatchFinder_CheckAndMoveAndRead(CMatchFinder *p) {
	if (MatchFinder_NeedMove(p)) MatchFinder_MoveBlock(p);
	MatchFinder_ReadBlock(p);
}

static void MatchFinder_CheckLimits(CMatchFinder *p) {
	if (p->pos == kMaxValForNormalize) MatchFinder_Normalize(p);
	if (!p->streamEndWasReached && p->keepSizeAfter == p->streamPos - p->pos) MatchFinder_CheckAndMoveAndRead(p);
	if (p->cyclicBufferPos == p->cyclicBufferSize) p->cyclicBufferPos = 0;
	MatchFinder_SetLimits(p);
}

#define MOVE_POS_RET MOVE_POS return offset;

static uint32_t * Hc_GetMatchesSpec(uint32_t lenLimit, uint32_t curMatch, uint32_t pos, const uint8_t *cur, CLzRef *son,
									uint32_t _cyclicBufferPos, uint32_t _cyclicBufferSize, uint32_t cutValue,
									uint32_t *distances, uint32_t maxLen) {
	son[_cyclicBufferPos] = curMatch;
	for (;;)
	{
		uint32_t delta = pos - curMatch;
		if (cutValue-- == 0 || delta >= _cyclicBufferSize) return distances;
		{
			const uint8_t *pb = cur - delta;
			curMatch = son[_cyclicBufferPos - delta + ((delta > _cyclicBufferPos) ? _cyclicBufferSize : 0)];
			if (pb[maxLen] == cur[maxLen] && *pb == *cur)
			{
				uint32_t len = 0;
				while (++len != lenLimit)
					if (pb[len] != cur[len])
						break;
				if (maxLen < len)
				{
					*distances++ = maxLen = len;
					*distances++ = delta - 1;
					if (len == lenLimit)
						return distances;
				}
			}
		}
	}
}

#define MF_PARAMS(p) p->pos, p->buffer, p->son, p->cyclicBufferPos, p->cyclicBufferSize, p->cutValue

static uint32_t Hc4_MatchFinder_GetMatches(CMatchFinder *p, uint32_t *distances) {
	uint32_t h2, h3, d2, d3, maxLen, offset, pos;
	uint32_t *hash;
	GET_MATCHES_HEADER(4)
	HASH4_CALC;
	hash = p->hash;
	pos = p->pos;
	d2 = pos - hash[                h2];
	d3 = pos - hash[kFix3HashSize + h3];
	curMatch = hash[kFix4HashSize + hv];
	hash[                h2] = pos;
	hash[kFix3HashSize + h3] = pos;
	hash[kFix4HashSize + hv] = pos;
	maxLen = 0;
	offset = 0;
	if (d2 < p->cyclicBufferSize && *(cur - d2) == *cur)
	{
		distances[0] = maxLen = 2;
		distances[1] = d2 - 1;
		offset = 2;
	}
	if (d2 != d3 && d3 < p->cyclicBufferSize && *(cur - d3) == *cur)
	{
		maxLen = 3;
		distances[offset + 1] = d3 - 1;
		offset += 2;
		d2 = d3;
	}
	if (offset != 0)
	{
		UPDATE_maxLen
		distances[offset - 2] = maxLen;
		if (maxLen == lenLimit)
		{
			p->son[p->cyclicBufferPos] = curMatch;
			MOVE_POS_RET;
		}
	}
	if (maxLen < 3) maxLen = 3;
	offset = (uint32_t)(Hc_GetMatchesSpec(lenLimit, curMatch, MF_PARAMS(p), distances + offset, maxLen) - (distances));
	MOVE_POS_RET
}

#define SKIP_HEADER(minLen) GET_MATCHES_HEADER2(minLen, continue)

static void Hc4_MatchFinder_Skip(CMatchFinder *p, uint32_t num) {
	do {
		uint32_t h2, h3;
		uint32_t *hash;
		SKIP_HEADER(4)
		HASH4_CALC;
		hash = p->hash;
		curMatch = hash[kFix4HashSize + hv];
		hash[                h2] =
		hash[kFix3HashSize + h3] =
		hash[kFix4HashSize + hv] = p->pos;
		p->son[p->cyclicBufferPos] = curMatch;
		MOVE_POS
	}
	while (--num != 0);
}

static uint32_t * GetMatchesSpec1(uint32_t lenLimit, uint32_t curMatch, uint32_t pos, const uint8_t *cur, CLzRef *son,
								  uint32_t _cyclicBufferPos, uint32_t _cyclicBufferSize, uint32_t cutValue,
								  uint32_t *distances, uint32_t maxLen) {
	CLzRef *ptr0 = son + (_cyclicBufferPos << 1) + 1;
	CLzRef *ptr1 = son + (_cyclicBufferPos << 1);
	uint32_t len0 = 0, len1 = 0;
	for (;;) {
		uint32_t delta = pos - curMatch;
		if (cutValue-- == 0 || delta >= _cyclicBufferSize)
		{
			*ptr0 = *ptr1 = kEmptyHashValue;
			return distances;
		}
		{
			CLzRef *pair = son + ((_cyclicBufferPos - delta + ((delta > _cyclicBufferPos) ? _cyclicBufferSize : 0)) << 1);
			const uint8_t *pb = cur - delta;
			uint32_t len = (len0 < len1 ? len0 : len1);
			if (pb[len] == cur[len])
			{
				if (++len != lenLimit && pb[len] == cur[len])
					while (++len != lenLimit)
						if (pb[len] != cur[len])
							break;
				if (maxLen < len)
				{
					*distances++ = maxLen = len;
					*distances++ = delta - 1;
					if (len == lenLimit)
					{
						*ptr1 = pair[0];
						*ptr0 = pair[1];
						return distances;
					}
				}
			}
			if (pb[len] < cur[len])
			{
				*ptr1 = curMatch;
				ptr1 = pair + 1;
				curMatch = *ptr1;
				len1 = len;
			}
			else
			{
				*ptr0 = curMatch;
				ptr0 = pair;
				curMatch = *ptr0;
				len0 = len;
			}
		}
	}
}

#define GET_MATCHES_FOOTER(offset, maxLen) \
offset = (uint32_t)(GetMatchesSpec1(lenLimit, curMatch, MF_PARAMS(p), \
distances + offset, maxLen) - distances); MOVE_POS_RET;

static uint32_t Bt2_MatchFinder_GetMatches(CMatchFinder *p, uint32_t *distances) {
	uint32_t offset;
	GET_MATCHES_HEADER(2)
	HASH2_CALC;
	curMatch = p->hash[hv];
	p->hash[hv] = p->pos;
	offset = 0;
	GET_MATCHES_FOOTER(offset, 1)
}

static void SkipMatchesSpec(uint32_t lenLimit, uint32_t curMatch, uint32_t pos, const uint8_t *cur, CLzRef *son,
							uint32_t _cyclicBufferPos, uint32_t _cyclicBufferSize, uint32_t cutValue) {
	CLzRef *ptr0 = son + (_cyclicBufferPos << 1) + 1;
	CLzRef *ptr1 = son + (_cyclicBufferPos << 1);
	uint32_t len0 = 0, len1 = 0;
	for (;;) {
		uint32_t delta = pos - curMatch;
		if (cutValue-- == 0 || delta >= _cyclicBufferSize)
		{
			*ptr0 = *ptr1 = kEmptyHashValue;
			return;
		}
		{
			CLzRef *pair = son + ((_cyclicBufferPos - delta + ((delta > _cyclicBufferPos) ? _cyclicBufferSize : 0)) << 1);
			const uint8_t *pb = cur - delta;
			uint32_t len = (len0 < len1 ? len0 : len1);
			if (pb[len] == cur[len])
			{
				while (++len != lenLimit)
					if (pb[len] != cur[len])
						break;
				{
					if (len == lenLimit)
					{
						*ptr1 = pair[0];
						*ptr0 = pair[1];
						return;
					}
				}
			}
			if (pb[len] < cur[len])
			{
				*ptr1 = curMatch;
				ptr1 = pair + 1;
				curMatch = *ptr1;
				len1 = len;
			}
			else
			{
				*ptr0 = curMatch;
				ptr0 = pair;
				curMatch = *ptr0;
				len0 = len;
			}
		}
	}
}

#define SKIP_FOOTER \
SkipMatchesSpec(lenLimit, curMatch, MF_PARAMS(p)); MOVE_POS;

static void Bt2_MatchFinder_Skip(CMatchFinder *p, uint32_t num) {
	do {
		SKIP_HEADER(2)
		HASH2_CALC;
		curMatch = p->hash[hv];
		p->hash[hv] = p->pos;
		SKIP_FOOTER
	}
	while (--num != 0);
}

static uint32_t Bt3_MatchFinder_GetMatches(CMatchFinder *p, uint32_t *distances) {
	uint32_t h2, d2, maxLen, offset, pos;
	uint32_t *hash;
	GET_MATCHES_HEADER(3)
	HASH3_CALC;
	hash = p->hash;
	pos = p->pos;
	d2 = pos - hash[h2];
	curMatch = hash[kFix3HashSize + hv];
	hash[h2] = pos;
	hash[kFix3HashSize + hv] = pos;
	maxLen = 2;
	offset = 0;
	if (d2 < p->cyclicBufferSize && *(cur - d2) == *cur)
	{
		UPDATE_maxLen
		distances[0] = maxLen;
		distances[1] = d2 - 1;
		offset = 2;
		if (maxLen == lenLimit)
		{
			SkipMatchesSpec(lenLimit, curMatch, MF_PARAMS(p));
			MOVE_POS_RET;
		}
	}
	GET_MATCHES_FOOTER(offset, maxLen)
}

static void Bt3_MatchFinder_Skip(CMatchFinder *p, uint32_t num) {
	do {
		uint32_t h2;
		uint32_t *hash;
		SKIP_HEADER(3)
		HASH3_CALC;
		hash = p->hash;
		curMatch = hash[kFix3HashSize + hv];
		hash[h2] =
		hash[kFix3HashSize + hv] = p->pos;
		SKIP_FOOTER
	}
	while (--num != 0);
}

static uint32_t Bt4_MatchFinder_GetMatches(CMatchFinder *p, uint32_t *distances) {
	uint32_t h2, h3, d2, d3, maxLen, offset, pos;
	uint32_t *hash;
	GET_MATCHES_HEADER(4)
	HASH4_CALC;
	hash = p->hash;
	pos = p->pos;
	d2 = pos - hash[                h2];
	d3 = pos - hash[kFix3HashSize + h3];
	curMatch = hash[kFix4HashSize + hv];
	hash[                h2] = pos;
	hash[kFix3HashSize + h3] = pos;
	hash[kFix4HashSize + hv] = pos;
	maxLen = 0;
	offset = 0;
	if (d2 < p->cyclicBufferSize && *(cur - d2) == *cur)
	{
		distances[0] = maxLen = 2;
		distances[1] = d2 - 1;
		offset = 2;
	}
	if (d2 != d3 && d3 < p->cyclicBufferSize && *(cur - d3) == *cur)
	{
		maxLen = 3;
		distances[offset + 1] = d3 - 1;
		offset += 2;
		d2 = d3;
	}
	if (offset != 0)
	{
		UPDATE_maxLen
		distances[offset - 2] = maxLen;
		if (maxLen == lenLimit)
		{
			SkipMatchesSpec(lenLimit, curMatch, MF_PARAMS(p));
			MOVE_POS_RET;
		}
	}
	if (maxLen < 3) maxLen = 3;
	GET_MATCHES_FOOTER(offset, maxLen)
}

static void Bt4_MatchFinder_Skip(CMatchFinder *p, uint32_t num) {
	do {
		uint32_t h2, h3;
		uint32_t *hash;
		SKIP_HEADER(4)
		HASH4_CALC;
		hash = p->hash;
		curMatch = hash[kFix4HashSize + hv];
		hash[                h2] =
		hash[kFix3HashSize + h3] =
		hash[kFix4HashSize + hv] = p->pos;
		SKIP_FOOTER
	}
	while (--num != 0);
}

static void MatchFinder_CreateVTable(CMatchFinder *p, IMatchFinder *vTable) {
	vTable->Init = (Mf_Init_Func)MatchFinder_Init;
	vTable->GetNumAvailableBytes = (Mf_GetNumAvailableBytes_Func)MatchFinder_GetNumAvailableBytes;
	vTable->GetPointerToCurrentPos = (Mf_GetPointerToCurrentPos_Func)MatchFinder_GetPointerToCurrentPos;
	if (!p->btMode)
	{
		vTable->GetMatches = (Mf_GetMatches_Func)Hc4_MatchFinder_GetMatches;
		vTable->Skip = (Mf_Skip_Func)Hc4_MatchFinder_Skip;
	}
	else if (p->numHashBytes == 2)
	{
		vTable->GetMatches = (Mf_GetMatches_Func)Bt2_MatchFinder_GetMatches;
		vTable->Skip = (Mf_Skip_Func)Bt2_MatchFinder_Skip;
	}
	else if (p->numHashBytes == 3)
	{
		vTable->GetMatches = (Mf_GetMatches_Func)Bt3_MatchFinder_GetMatches;
		vTable->Skip = (Mf_Skip_Func)Bt3_MatchFinder_Skip;
	}
	else
	{
		vTable->GetMatches = (Mf_GetMatches_Func)Bt4_MatchFinder_GetMatches;
		vTable->Skip = (Mf_Skip_Func)Bt4_MatchFinder_Skip;
	}
}

static int LzmaEnc_Alloc(CLzmaEnc *p, uint32_t keepWindowSize, ISzAlloc *alloc, ISzAlloc *allocBig) {
	uint32_t beforeSize = kNumOpts;
	if (!RangeEnc_Alloc(&p->rc, alloc)) return SZ_ERROR_MEM;

	{
		unsigned lclp = p->lc + p->lp;
		if (p->litProbs == 0 || p->saveState.litProbs == 0 || p->lclp != lclp)
		{
			LzmaEnc_FreeLits(p, alloc);
			p->litProbs = (uint16_t *)alloc->Alloc(alloc, ((uint32_t)0x300 << lclp) * sizeof(uint16_t));
			p->saveState.litProbs = (uint16_t *)alloc->Alloc(alloc, ((uint32_t)0x300 << lclp) * sizeof(uint16_t));
			if (p->litProbs == 0 || p->saveState.litProbs == 0)
			{
				LzmaEnc_FreeLits(p, alloc);
				return SZ_ERROR_MEM;
			}
			p->lclp = lclp;
		}
	}

	p->matchFinderBase.bigHash = (uint8_t)(p->dictSize > kBigHashDicLimit ? 1 : 0);

	if (beforeSize + p->dictSize < keepWindowSize) beforeSize = keepWindowSize - p->dictSize;
	{
		if (!MatchFinder_Create(&p->matchFinderBase, p->dictSize, beforeSize, p->numFastBytes, LZMA_MATCH_LEN_MAX, allocBig)) return SZ_ERROR_MEM;
		p->matchFinderObj = &p->matchFinderBase;
		MatchFinder_CreateVTable(&p->matchFinderBase, &p->matchFinder);
	}
	return SZ_OK;
}

static void RangeEnc_Init(CRangeEnc *p) {
	p->low = 0;
	p->range = 0xFFFFFFFF;
	p->cacheSize = 1;
	p->cache = 0;
	p->buf = p->bufBase;
	p->processed = 0;
	p->res = SZ_OK;
}

static void LenEnc_Init(CLenEnc *p) {
	unsigned i;
	p->choice = p->choice2 = kProbInitValue;
	for (i = 0; i < (LZMA_NUM_PB_STATES_MAX << kLenNumLowBits); i++) p->low[i] = kProbInitValue;
	for (i = 0; i < (LZMA_NUM_PB_STATES_MAX << kLenNumMidBits); i++) p->mid[i] = kProbInitValue;
	for (i = 0; i < kLenNumHighSymbols; i++) p->high[i] = kProbInitValue;
}

static void LzmaEnc_Init(CLzmaEnc *p) {
	p->state = 0;
	for (uint32_t i = 0 ; i < LZMA_NUM_REPS; i++) p->reps[i] = 0;
	RangeEnc_Init(&p->rc);
	for (uint32_t i = 0; i < kNumStates; i++)
	{
		for (uint32_t j = 0; j < LZMA_NUM_PB_STATES_MAX; j++)
		{
			p->isMatch[i][j] = kProbInitValue;
			p->isRep0Long[i][j] = kProbInitValue;
		}
		p->isRep[i] = kProbInitValue;
		p->isRepG0[i] = kProbInitValue;
		p->isRepG1[i] = kProbInitValue;
		p->isRepG2[i] = kProbInitValue;
	}
	{
		uint32_t num = (uint32_t)0x300 << (p->lp + p->lc);
		uint16_t *probs = p->litProbs;
		for (uint32_t i = 0; i < num; i++) probs[i] = kProbInitValue;
	}
	{
		for (uint32_t i = 0; i < kNumLenToPosStates; i++)
		{
			uint16_t *probs = p->posSlotEncoder[i];
			for (uint32_t j = 0; j < (1 << kNumPosSlotBits); j++) probs[j] = kProbInitValue;
		}
	}
	{
		for (uint32_t i = 0; i < kNumFullDistances - kEndPosModelIndex; i++) p->posEncoders[i] = kProbInitValue;
	}
	LenEnc_Init(&p->lenEnc.p);
	LenEnc_Init(&p->repLenEnc.p);
	for (uint32_t i = 0; i < (1 << kNumAlignBits); i++) p->posAlignEncoder[i] = kProbInitValue;
	p->optimumEndIndex = 0;
	p->optimumCurrentIndex = 0;
	p->additionalOffset = 0;
	p->pbMask = (1 << p->pb) - 1;
	p->lpMask = (1 << p->lp) - 1;
}

#define kDicLogSizeMaxCompress 32

static unsigned char _BitScanReverse(unsigned long *firstBit1Index, unsigned long scanNum) {
	unsigned char isNonzero;
	isNonzero = (unsigned char)scanNum;
	if (scanNum != 0) {
		size_t index = __builtin_clz(scanNum);
		*firstBit1Index = index ^ 31;
	}
	else *firstBit1Index = 0;
	return isNonzero;
}

#define BSR2_RET(pos, res) { unsigned long i; _BitScanReverse(&i, (pos)); res = (i + i) + ((pos >> (i - 1)) & 1); }

static uint32_t GetPosSlot1(uint32_t pos) {
	uint32_t res;
	BSR2_RET(pos, res);
	return res;
}

#define GetPosSlot2(pos, res) { BSR2_RET(pos, res); }
#define GetPosSlot(pos, res) { if (pos < 2) res = pos; else BSR2_RET(pos, res); }

#define GET_PRICEa(prob, symbol) \
ProbPrices[((prob) ^ ((-((int)(symbol))) & (kBitModelTotal - 1))) >> kNumMoveReducingBits];

static uint32_t RcTree_ReverseGetPrice(const uint16_t *probs, int numBitLevels, uint32_t symbol, const uint32_t *ProbPrices) {
	uint32_t price = 0;
	uint32_t m = 1;
	for (int i = numBitLevels; i != 0; i--)
	{
		uint32_t bit = symbol & 1;
		symbol >>= 1;
		price += GET_PRICEa(probs[m], bit);
		m = (m << 1) | bit;
	}
	return price;
}

static uint32_t RcTree_GetPrice(const uint16_t *probs, int numBitLevels, uint32_t symbol, const uint32_t *ProbPrices) {
	uint32_t price = 0;
	symbol |= (1 << numBitLevels);
	while (symbol != 1)
	{
		price += GET_PRICEa(probs[symbol >> 1], symbol & 1);
		symbol >>= 1;
	}
	return price;
}

static void FillDistancesPrices(CLzmaEnc *p) {
	uint32_t tempPrices[kNumFullDistances];
	uint32_t lenToPosState;
	for (uint32_t i = kStartPosModelIndex; i < kNumFullDistances; i++)
	{
		uint32_t posSlot = GetPosSlot1(i);
		uint32_t footerBits = ((posSlot >> 1) - 1);
		uint32_t base = ((2 | (posSlot & 1)) << footerBits);
		tempPrices[i] = RcTree_ReverseGetPrice(p->posEncoders + base - posSlot - 1, footerBits, i - base, p->ProbPrices);
	}

	for (lenToPosState = 0; lenToPosState < kNumLenToPosStates; lenToPosState++)
	{
		const uint16_t *encoder = p->posSlotEncoder[lenToPosState];
		uint32_t *posSlotPrices = p->posSlotPrices[lenToPosState];
		for (uint32_t posSlot = 0; posSlot < p->distTableSize; posSlot++)
			posSlotPrices[posSlot] = RcTree_GetPrice(encoder, kNumPosSlotBits, posSlot, p->ProbPrices);
		for (uint32_t posSlot = kEndPosModelIndex; posSlot < p->distTableSize; posSlot++)
			posSlotPrices[posSlot] += ((((posSlot >> 1) - 1) - kNumAlignBits) << kNumBitPriceShiftBits);

		{
			uint32_t *distancesPrices = p->distancesPrices[lenToPosState];
			uint32_t i;
			for (i = 0; i < kStartPosModelIndex; i++) distancesPrices[i] = posSlotPrices[i];
			for (; i < kNumFullDistances; i++) distancesPrices[i] = posSlotPrices[GetPosSlot1(i)] + tempPrices[i];
		}
	}
	p->matchPriceCount = 0;
}

static void FillAlignPrices(CLzmaEnc *p) {
	for (uint32_t i = 0; i < kAlignTableSize; i++)
		p->alignPrices[i] = RcTree_ReverseGetPrice(p->posAlignEncoder, kNumAlignBits, i, p->ProbPrices);
	p->alignPriceCount = 0;
}

#define GET_PRICE_0a(prob) ProbPrices[(prob) >> kNumMoveReducingBits]
#define GET_PRICE_1a(prob) ProbPrices[((prob) ^ (kBitModelTotal - 1)) >> kNumMoveReducingBits]

static void LenEnc_SetPrices(CLenEnc *p, uint32_t posState, uint32_t numSymbols, uint32_t *prices, const uint32_t *ProbPrices) {
	uint32_t a0 = GET_PRICE_0a(p->choice);
	uint32_t a1 = GET_PRICE_1a(p->choice);
	uint32_t b0 = a1 + GET_PRICE_0a(p->choice2);
	uint32_t b1 = a1 + GET_PRICE_1a(p->choice2);
	uint32_t i = 0;
	for (i = 0; i < kLenNumLowSymbols; i++)
	{
		if (i >= numSymbols) return;
		prices[i] = a0 + RcTree_GetPrice(p->low + (posState << kLenNumLowBits), kLenNumLowBits, i, ProbPrices);
	}
	for (; i < kLenNumLowSymbols + kLenNumMidSymbols; i++)
	{
		if (i >= numSymbols) return;
		prices[i] = b0 + RcTree_GetPrice(p->mid + (posState << kLenNumMidBits), kLenNumMidBits, i - kLenNumLowSymbols, ProbPrices);
	}
	for (; i < numSymbols; i++)
		prices[i] = b1 + RcTree_GetPrice(p->high, kLenNumHighBits, i - kLenNumLowSymbols - kLenNumMidSymbols, ProbPrices);
}

static void LenPriceEnc_UpdateTable(CLenPriceEnc *p, uint32_t posState, const uint32_t *ProbPrices) {
	LenEnc_SetPrices(&p->p, posState, p->tableSize, p->prices[posState], ProbPrices);
	p->counters[posState] = p->tableSize;
}

static void LenPriceEnc_UpdateTables(CLenPriceEnc *p, uint32_t numPosStates, const uint32_t *ProbPrices) {
	uint32_t posState;
	for (posState = 0; posState < numPosStates; posState++)
		LenPriceEnc_UpdateTable(p, posState, ProbPrices);
}

static void LzmaEnc_InitPrices(CLzmaEnc *p) {
	if (!p->fastMode)
	{
		FillDistancesPrices(p);
		FillAlignPrices(p);
	}
	p->lenEnc.tableSize =
	p->repLenEnc.tableSize =
	p->numFastBytes + 1 - LZMA_MATCH_LEN_MIN;
	LenPriceEnc_UpdateTables(&p->lenEnc, 1 << p->pb, p->ProbPrices);
	LenPriceEnc_UpdateTables(&p->repLenEnc, 1 << p->pb, p->ProbPrices);
}

static int LzmaEnc_AllocAndInit(CLzmaEnc *p, uint32_t keepWindowSize, ISzAlloc *alloc, ISzAlloc *allocBig) {
	uint32_t i;
	for (i = 0; i < (uint32_t)kDicLogSizeMaxCompress; i++)
		if (p->dictSize <= ((uint32_t)1 << i))
			break;
	p->distTableSize = i * 2;
	p->finished = 0;
	p->result = SZ_OK;
	RINOK(LzmaEnc_Alloc(p, keepWindowSize, alloc, allocBig));
	LzmaEnc_Init(p);
	LzmaEnc_InitPrices(p);
	p->nowPos64 = 0;
	return SZ_OK;
}

static int LzmaEnc_MemPrepare(CLzmaEncHandle pp, const uint8_t *src, size_t srcLen,
							  uint32_t keepWindowSize, ISzAlloc *alloc, ISzAlloc *allocBig) {
	CLzmaEnc *p = (CLzmaEnc *)pp;
	LzmaEnc_SetInputBuf(p, src, srcLen);
	p->needInit = 1;
	return LzmaEnc_AllocAndInit(p, keepWindowSize, alloc, allocBig);
}

static int CheckErrors(CLzmaEnc *p) {
	if (p->result != SZ_OK) return p->result;
	if (p->rc.res != SZ_OK) p->result = SZ_ERROR_WRITE;
	if (p->matchFinderBase.result != SZ_OK) p->result = SZ_ERROR_READ;
	if (p->result != SZ_OK) p->finished = 1;
	return p->result;
}

static void RangeEnc_FlushStream(CRangeEnc *p) {
	size_t num;
	if (p->res != SZ_OK) return;
	num = p->buf - p->bufBase;
	if (num != p->outStream->Write(p->outStream, p->bufBase, num)) p->res = SZ_ERROR_WRITE;
	p->processed += num;
	p->buf = p->bufBase;
}

static void RangeEnc_ShiftLow(CRangeEnc *p) {
	if ((uint32_t)p->low < (uint32_t)0xFF000000 || (unsigned)(p->low >> 32) != 0)
	{
		uint8_t temp = p->cache;
		do {
			uint8_t *buf = p->buf;
			*buf++ = (uint8_t)(temp + (uint8_t)(p->low >> 32));
			p->buf = buf;
			if (buf == p->bufLim) RangeEnc_FlushStream(p);
			temp = 0xFF;
		} while (--p->cacheSize != 0);
		p->cache = (uint8_t)((uint32_t)p->low >> 24);
	}
	p->cacheSize++;
	p->low = (uint32_t)p->low << 8;
}

static void RangeEnc_EncodeBit(CRangeEnc *p, uint16_t *prob, uint32_t symbol) {
	uint32_t ttt = *prob;
	uint32_t newBound = (p->range >> kNumBitModelTotalBits) * ttt;
	if (symbol == 0)
	{
		p->range = newBound;
		ttt += (kBitModelTotal - ttt) >> kNumMoveBits;
	}
	else
	{
		p->low += newBound;
		p->range -= newBound;
		ttt -= ttt >> kNumMoveBits;
	}
	*prob = (uint16_t)ttt;
	if (p->range < kTopValue)
	{
		p->range <<= 8;
		RangeEnc_ShiftLow(p);
	}
}

static void RcTree_Encode(CRangeEnc *rc, uint16_t *probs, int numBitLevels, uint32_t symbol) {
	uint32_t m = 1;
	for (int i = numBitLevels; i != 0;)
	{
		uint32_t bit;
		i--;
		bit = (symbol >> i) & 1;
		RangeEnc_EncodeBit(rc, probs + m, bit);
		m = (m << 1) | bit;
	}
}

static void LenEnc_Encode(CLenEnc *p, CRangeEnc *rc, uint32_t symbol, uint32_t posState) {
	if (symbol < kLenNumLowSymbols)
	{
		RangeEnc_EncodeBit(rc, &p->choice, 0);
		RcTree_Encode(rc, p->low + (posState << kLenNumLowBits), kLenNumLowBits, symbol);
	}
	else
	{
		RangeEnc_EncodeBit(rc, &p->choice, 1);
		if (symbol < kLenNumLowSymbols + kLenNumMidSymbols)
		{
			RangeEnc_EncodeBit(rc, &p->choice2, 0);
			RcTree_Encode(rc, p->mid + (posState << kLenNumMidBits), kLenNumMidBits, symbol - kLenNumLowSymbols);
		}
		else
		{
			RangeEnc_EncodeBit(rc, &p->choice2, 1);
			RcTree_Encode(rc, p->high, kLenNumHighBits, symbol - kLenNumLowSymbols - kLenNumMidSymbols);
		}
	}
}

static void LenEnc_Encode2(CLenPriceEnc *p, CRangeEnc *rc, uint32_t symbol, uint32_t posState, uint8_t updatePrice, const uint32_t *ProbPrices) {
	LenEnc_Encode(&p->p, rc, symbol, posState);
	if (updatePrice)
		if (--p->counters[posState] == 0)
			LenPriceEnc_UpdateTable(p, posState, ProbPrices);
}

#define GetLenToPosState(len) (((len) < kNumLenToPosStates + 1) ? (len) - 2 : kNumLenToPosStates - 1)

static void RangeEnc_EncodeDirectBits(CRangeEnc *p, uint32_t value, unsigned numBits) {
	do {
		p->range >>= 1;
		p->low += p->range & (0 - ((value >> --numBits) & 1));
		if (p->range < kTopValue)
		{
			p->range <<= 8;
			RangeEnc_ShiftLow(p);
		}
	} while (numBits != 0);
}

static void RcTree_ReverseEncode(CRangeEnc *rc, uint16_t *probs, int numBitLevels, uint32_t symbol) {
	uint32_t m = 1;
	for (int i = 0; i < numBitLevels; i++)
	{
		uint32_t bit = symbol & 1;
		RangeEnc_EncodeBit(rc, probs + m, bit);
		m = (m << 1) | bit;
		symbol >>= 1;
	}
}

static void WriteEndMarker(CLzmaEnc *p, uint32_t posState) {
	uint32_t len;
	RangeEnc_EncodeBit(&p->rc, &p->isMatch[p->state][posState], 1);
	RangeEnc_EncodeBit(&p->rc, &p->isRep[p->state], 0);
	const int kMatchNextStates[kNumStates]   = {7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10};
	p->state = kMatchNextStates[p->state];
	len = LZMA_MATCH_LEN_MIN;
	LenEnc_Encode2(&p->lenEnc, &p->rc, len - LZMA_MATCH_LEN_MIN, posState, !p->fastMode, p->ProbPrices);
	RcTree_Encode(&p->rc, p->posSlotEncoder[GetLenToPosState(len)], kNumPosSlotBits, (1 << kNumPosSlotBits) - 1);
	RangeEnc_EncodeDirectBits(&p->rc, (((uint32_t)1 << 30) - 1) >> kNumAlignBits, 30 - kNumAlignBits);
	RcTree_ReverseEncode(&p->rc, p->posAlignEncoder, kNumAlignBits, kAlignMask);
}

static void RangeEnc_FlushData(CRangeEnc *p) {
	for (int i = 0; i < 5; i++) RangeEnc_ShiftLow(p);
}

static int Flush(CLzmaEnc *p, uint32_t nowPos) {
	p->finished = 1;
	if (p->writeEndMark) WriteEndMarker(p, nowPos & p->pbMask);
	RangeEnc_FlushData(&p->rc);
	RangeEnc_FlushStream(&p->rc);
	return CheckErrors(p);
}

static uint32_t ReadMatchDistances(CLzmaEnc *p, uint32_t *numDistancePairsRes) {
	uint32_t lenRes = 0, numPairs;
	p->numAvail = p->matchFinder.GetNumAvailableBytes(p->matchFinderObj);
	numPairs = p->matchFinder.GetMatches(p->matchFinderObj, p->matches);
	if (numPairs > 0)
	{
		lenRes = p->matches[numPairs - 2];
		if (lenRes == p->numFastBytes)
		{
			uint32_t numAvail = p->numAvail;
			if (numAvail > LZMA_MATCH_LEN_MAX)
				numAvail = LZMA_MATCH_LEN_MAX;
			{
				const uint8_t *pbyCur = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - 1;
				const uint8_t *pby = pbyCur + lenRes;
				ptrdiff_t dif = (ptrdiff_t)-1 - p->matches[numPairs - 1];
				const uint8_t *pbyLim = pbyCur + numAvail;
				for (; pby != pbyLim && *pby == pby[dif]; pby++);
				lenRes = (uint32_t)(pby - pbyCur);
			}
		}
	}
	p->additionalOffset++;
	*numDistancePairsRes = numPairs;
	return lenRes;
}

static void LitEnc_Encode(CRangeEnc *p, uint16_t *probs, uint32_t symbol) {
	symbol |= 0x100;
	do {
		RangeEnc_EncodeBit(p, probs + (symbol >> 8), (symbol >> 7) & 1);
		symbol <<= 1;
	} while (symbol < 0x10000);
}

static void MovePos(CLzmaEnc *p, uint32_t num) {
	if (num != 0)
	{
		p->additionalOffset += num;
		p->matchFinder.Skip(p->matchFinderObj, num);
	}
}

#define ChangePair(smallDist, bigDist) (((bigDist) >> 7) > (smallDist))

static uint32_t GetOptimumFast(CLzmaEnc *p, uint32_t *backRes) {
	uint32_t numAvail, mainLen, mainDist, numPairs, repIndex, repLen, i;
	if (p->additionalOffset == 0) mainLen = ReadMatchDistances(p, &numPairs);
	else
	{
		mainLen = p->longestMatchLength;
		numPairs = p->numPairs;
	}

	numAvail = p->numAvail;
	*backRes = (uint32_t)-1;
	if (numAvail < 2) return 1;
	if (numAvail > LZMA_MATCH_LEN_MAX) numAvail = LZMA_MATCH_LEN_MAX;
	const uint8_t * data = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - 1;

	repLen = repIndex = 0;
	for (i = 0; i < LZMA_NUM_REPS; i++)
	{
		uint32_t len;
		const uint8_t *data2 = data - p->reps[i] - 1;
		if (data[0] != data2[0] || data[1] != data2[1]) continue;
		for (len = 2; len < numAvail && data[len] == data2[len]; len++);
		if (len >= p->numFastBytes)
		{
			*backRes = i;
			MovePos(p, len - 1);
			return len;
		}
		if (len > repLen)
		{
			repIndex = i;
			repLen = len;
		}
	}
	const uint32_t * matches = p->matches;
	if (mainLen >= p->numFastBytes)
	{
		*backRes = matches[numPairs - 1] + LZMA_NUM_REPS;
		MovePos(p, mainLen - 1);
		return mainLen;
	}
	mainDist = 0;
	if (mainLen >= 2)
	{
		mainDist = matches[numPairs - 1];
		while (numPairs > 2 && mainLen == matches[numPairs - 4] + 1)
		{
			if (!ChangePair(matches[numPairs - 3], mainDist)) break;
			numPairs -= 2;
			mainLen = matches[numPairs - 2];
			mainDist = matches[numPairs - 1];
		}
		if (mainLen == 2 && mainDist >= 0x80) mainLen = 1;
	}
	if (repLen >= 2 && (
						(repLen + 1 >= mainLen) ||
						(repLen + 2 >= mainLen && mainDist >= (1 << 9)) ||
						(repLen + 3 >= mainLen && mainDist >= (1 << 15))))
	{
		*backRes = repIndex;
		MovePos(p, repLen - 1);
		return repLen;
	}
	if (mainLen < 2 || numAvail <= 2) return 1;
	p->longestMatchLength = ReadMatchDistances(p, &p->numPairs);
	if (p->longestMatchLength >= 2)
	{
		uint32_t newDistance = matches[p->numPairs - 1];
		if ((p->longestMatchLength >= mainLen && newDistance < mainDist) ||
			(p->longestMatchLength == mainLen + 1 && !ChangePair(mainDist, newDistance)) ||
			(p->longestMatchLength > mainLen + 1) ||
			(p->longestMatchLength + 1 >= mainLen && mainLen >= 3 && ChangePair(newDistance, mainDist)))
			return 1;
	}
	data = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - 1;
	for (i = 0; i < LZMA_NUM_REPS; i++)
	{
		uint32_t len, limit;
		const uint8_t *data2 = data - p->reps[i] - 1;
		if (data[0] != data2[0] || data[1] != data2[1]) continue;
		limit = mainLen - 1;
		for (len = 2; len < limit && data[len] == data2[len]; len++);
		if (len >= limit) return 1;
	}
	*backRes = mainDist + LZMA_NUM_REPS;
	MovePos(p, mainLen - 2);
	return mainLen;
}

#define LIT_PROBS(pos, prevByte) (p->litProbs + ((((pos) & p->lpMask) << p->lc) + ((prevByte) >> (8 - p->lc))) * (uint32_t)0x300)
#define GET_PRICE_0(prob) p->ProbPrices[(prob) >> kNumMoveReducingBits]
#define IsCharState(s) ((s) < 7)

static uint32_t LitEnc_GetPriceMatched(const uint16_t *probs, uint32_t symbol, uint32_t matchByte, const uint32_t *ProbPrices) {
	uint32_t price = 0;
	uint32_t offs = 0x100;
	symbol |= 0x100;
	do {
		matchByte <<= 1;
		price += GET_PRICEa(probs[offs + (matchByte & offs) + (symbol >> 8)], (symbol >> 7) & 1);
		symbol <<= 1;
		offs &= ~(matchByte ^ symbol);
	} while (symbol < 0x10000);
	return price;
}

static uint32_t LitEnc_GetPrice(const uint16_t *probs, uint32_t symbol, const uint32_t *ProbPrices) {
	uint32_t price = 0;
	symbol |= 0x100;
	do {
		price += GET_PRICEa(probs[symbol >> 8], (symbol >> 7) & 1);
		symbol <<= 1;
	} while (symbol < 0x10000);
	return price;
}

#define MakeAsChar(p) (p)->backPrev = (uint32_t)(-1); (p)->prev1IsChar = 0;
#define GET_PRICE_1(prob) p->ProbPrices[((prob) ^ (kBitModelTotal - 1)) >> kNumMoveReducingBits]

static uint32_t GetRepLen1Price(CLzmaEnc *p, uint32_t state, uint32_t posState) {
	return
	GET_PRICE_0(p->isRepG0[state]) +
	GET_PRICE_0(p->isRep0Long[state][posState]);
}

#define MakeAsShortRep(p) (p)->backPrev = 0; (p)->prev1IsChar = 0;
#define kInfinityPrice (1 << 30)
#define GET_PRICE(prob, symbol) \
p->ProbPrices[((prob) ^ (((-(int)(symbol))) & (kBitModelTotal - 1))) >> kNumMoveReducingBits];

static uint32_t GetPureRepPrice(CLzmaEnc *p, uint32_t repIndex, uint32_t state, uint32_t posState) {
	uint32_t price;
	if (repIndex == 0)
	{
		price = GET_PRICE_0(p->isRepG0[state]);
		price += GET_PRICE_1(p->isRep0Long[state][posState]);
	}
	else
	{
		price = GET_PRICE_1(p->isRepG0[state]);
		if (repIndex == 1) price += GET_PRICE_0(p->isRepG1[state]);
		else
		{
			price += GET_PRICE_1(p->isRepG1[state]);
			price += GET_PRICE(p->isRepG2[state], repIndex - 2);
		}
	}
	return price;
}

static uint32_t Backward(CLzmaEnc *p, uint32_t *backRes, uint32_t cur) {
	uint32_t posMem = p->opt[cur].posPrev;
	uint32_t backMem = p->opt[cur].backPrev;
	p->optimumEndIndex = cur;
	do {
		if (p->opt[cur].prev1IsChar)
		{
			MakeAsChar(&p->opt[posMem])
			p->opt[posMem].posPrev = posMem - 1;
			if (p->opt[cur].prev2)
			{
				p->opt[posMem - 1].prev1IsChar = 0;
				p->opt[posMem - 1].posPrev = p->opt[cur].posPrev2;
				p->opt[posMem - 1].backPrev = p->opt[cur].backPrev2;
			}
		}
		{
			uint32_t posPrev = posMem;
			uint32_t backCur = backMem;
			backMem = p->opt[posPrev].backPrev;
			posMem = p->opt[posPrev].posPrev;
			p->opt[posPrev].backPrev = backCur;
			p->opt[posPrev].posPrev = cur;
			cur = posPrev;
		}
	} while (cur != 0);
	*backRes = p->opt[0].backPrev;
	p->optimumCurrentIndex  = p->opt[0].posPrev;
	return p->optimumCurrentIndex;
}

#define IsShortRep(p) ((p)->backPrev == 0)

static uint32_t GetRepPrice(CLzmaEnc *p, uint32_t repIndex, uint32_t len, uint32_t state, uint32_t posState) {
	return p->repLenEnc.prices[posState][len - LZMA_MATCH_LEN_MIN] +
	GetPureRepPrice(p, repIndex, state, posState);
}

static uint32_t GetOptimum(CLzmaEnc *p, uint32_t position, uint32_t *backRes) {
	uint32_t numAvail, mainLen, numPairs, repMaxIndex, i, posState, lenEnd, len, cur;
	uint32_t matchPrice, repMatchPrice, normalMatchPrice;
	uint32_t reps[LZMA_NUM_REPS], repLens[LZMA_NUM_REPS];
	uint32_t *matches;
	const uint8_t *data;
	uint8_t curByte, matchByte;
	if (p->optimumEndIndex != p->optimumCurrentIndex)
	{
		const COptimal *opt = &p->opt[p->optimumCurrentIndex];
		uint32_t lenRes = opt->posPrev - p->optimumCurrentIndex;
		*backRes = opt->backPrev;
		p->optimumCurrentIndex = opt->posPrev;
		return lenRes;
	}
	p->optimumCurrentIndex = p->optimumEndIndex = 0;
	if (p->additionalOffset == 0) mainLen = ReadMatchDistances(p, &numPairs);
	else
	{
		mainLen = p->longestMatchLength;
		numPairs = p->numPairs;
	}
	numAvail = p->numAvail;
	if (numAvail < 2)
	{
		*backRes = (uint32_t)(-1);
		return 1;
	}
	if (numAvail > LZMA_MATCH_LEN_MAX) numAvail = LZMA_MATCH_LEN_MAX;
	data = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - 1;
	repMaxIndex = 0;
	for (i = 0; i < LZMA_NUM_REPS; i++)
	{
		uint32_t lenTest;
		const uint8_t *data2;
		reps[i] = p->reps[i];
		data2 = data - reps[i] - 1;
		if (data[0] != data2[0] || data[1] != data2[1])
		{
			repLens[i] = 0;
			continue;
		}
		for (lenTest = 2; lenTest < numAvail && data[lenTest] == data2[lenTest]; lenTest++);
		repLens[i] = lenTest;
		if (lenTest > repLens[repMaxIndex]) repMaxIndex = i;
	}
	if (repLens[repMaxIndex] >= p->numFastBytes)
	{
		uint32_t lenRes;
		*backRes = repMaxIndex;
		lenRes = repLens[repMaxIndex];
		MovePos(p, lenRes - 1);
		return lenRes;
	}
	matches = p->matches;
	if (mainLen >= p->numFastBytes)
	{
		*backRes = matches[numPairs - 1] + LZMA_NUM_REPS;
		MovePos(p, mainLen - 1);
		return mainLen;
	}
	curByte = *data;
	matchByte = *(data - (reps[0] + 1));
	if (mainLen < 2 && curByte != matchByte && repLens[repMaxIndex] < 2)
	{
		*backRes = (uint32_t)-1;
		return 1;
	}
	p->opt[0].state = (CState)p->state;
	posState = (position & p->pbMask);

	{
		const uint16_t *probs = LIT_PROBS(position, *(data - 1));
		p->opt[1].price = GET_PRICE_0(p->isMatch[p->state][posState]) +
		(!IsCharState(p->state) ?
		 LitEnc_GetPriceMatched(probs, curByte, matchByte, p->ProbPrices) :
		 LitEnc_GetPrice(probs, curByte, p->ProbPrices));
	}
	MakeAsChar(&p->opt[1]);
	matchPrice = GET_PRICE_1(p->isMatch[p->state][posState]);
	repMatchPrice = matchPrice + GET_PRICE_1(p->isRep[p->state]);
	if (matchByte == curByte)
	{
		uint32_t shortRepPrice = repMatchPrice + GetRepLen1Price(p, p->state, posState);
		if (shortRepPrice < p->opt[1].price)
		{
			p->opt[1].price = shortRepPrice;
			MakeAsShortRep(&p->opt[1]);
		}
	}
	lenEnd = ((mainLen >= repLens[repMaxIndex]) ? mainLen : repLens[repMaxIndex]);
	if (lenEnd < 2)
	{
		*backRes = p->opt[1].backPrev;
		return 1;
	}
	p->opt[1].posPrev = 0;
	for (i = 0; i < LZMA_NUM_REPS; i++) p->opt[0].backs[i] = reps[i];
	len = lenEnd;
	do
		p->opt[len--].price = kInfinityPrice;
	while (len >= 2);
	for (i = 0; i < LZMA_NUM_REPS; i++)
	{
		uint32_t repLen = repLens[i];
		uint32_t price;
		if (repLen < 2) continue;
		price = repMatchPrice + GetPureRepPrice(p, i, p->state, posState);
		do {
			uint32_t curAndLenPrice = price + p->repLenEnc.prices[posState][repLen - 2];
			COptimal *opt = &p->opt[repLen];
			if (curAndLenPrice < opt->price)
			{
				opt->price = curAndLenPrice;
				opt->posPrev = 0;
				opt->backPrev = i;
				opt->prev1IsChar = 0;
			}
		} while (--repLen >= 2);
	}
	normalMatchPrice = matchPrice + GET_PRICE_0(p->isRep[p->state]);
	len = ((repLens[0] >= 2) ? repLens[0] + 1 : 2);
	if (len <= mainLen)
	{
		uint32_t offs = 0;
		while (len > matches[offs]) offs += 2;
		for (; ; len++)
		{
			COptimal *opt;
			uint32_t distance = matches[offs + 1];

			uint32_t curAndLenPrice = normalMatchPrice + p->lenEnc.prices[posState][len - LZMA_MATCH_LEN_MIN];
			uint32_t lenToPosState = GetLenToPosState(len);
			if (distance < kNumFullDistances)
				curAndLenPrice += p->distancesPrices[lenToPosState][distance];
			else
			{
				uint32_t slot;
				GetPosSlot2(distance, slot);
				curAndLenPrice += p->alignPrices[distance & kAlignMask] + p->posSlotPrices[lenToPosState][slot];
			}
			opt = &p->opt[len];
			if (curAndLenPrice < opt->price)
			{
				opt->price = curAndLenPrice;
				opt->posPrev = 0;
				opt->backPrev = distance + LZMA_NUM_REPS;
				opt->prev1IsChar = 0;
			}
			if (len == matches[offs])
			{
				offs += 2;
				if (offs == numPairs) break;
			}
		}
	}

	cur = 0;
	const int kRepNextStates[kNumStates]     = {8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11};
	const int kMatchNextStates[kNumStates]   = {7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10};
	const int kLiteralNextStates[kNumStates] = {0, 0, 0, 0, 1, 2, 3, 4,  5,  6,   4, 5};
	const int kShortRepNextStates[kNumStates]= {9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11};
	for (;;)
	{
		uint32_t numAvailFull, newLen, numPairs, posPrev, state, posState, startLen;
		uint32_t curPrice, curAnd1Price, matchPrice, repMatchPrice;
		uint8_t nextIsChar;
		uint8_t curByte, matchByte;
		const uint8_t *data;
		COptimal *curOpt;
		COptimal *nextOpt;
		cur++;
		if (cur == lenEnd) return Backward(p, backRes, cur);
		newLen = ReadMatchDistances(p, &numPairs);
		if (newLen >= p->numFastBytes)
		{
			p->numPairs = numPairs;
			p->longestMatchLength = newLen;
			return Backward(p, backRes, cur);
		}
		position++;
		curOpt = &p->opt[cur];
		posPrev = curOpt->posPrev;
		if (curOpt->prev1IsChar)
		{
			posPrev--;
			if (curOpt->prev2)
			{
				state = p->opt[curOpt->posPrev2].state;
				if (curOpt->backPrev2 < LZMA_NUM_REPS) state = kRepNextStates[state];
				else state = kMatchNextStates[state];
			}
			else state = p->opt[posPrev].state;
			state = kLiteralNextStates[state];
		}
		else state = p->opt[posPrev].state;
		if (posPrev == cur - 1)
		{
			if (IsShortRep(curOpt)) state = kShortRepNextStates[state];
			else state = kLiteralNextStates[state];
		}
		else
		{
			uint32_t pos;
			const COptimal *prevOpt;
			if (curOpt->prev1IsChar && curOpt->prev2)
			{
				posPrev = curOpt->posPrev2;
				pos = curOpt->backPrev2;
				state = kRepNextStates[state];
			}
			else
			{
				pos = curOpt->backPrev;
				if (pos < LZMA_NUM_REPS) state = kRepNextStates[state];
				else state = kMatchNextStates[state];
			}
			prevOpt = &p->opt[posPrev];
			if (pos < LZMA_NUM_REPS)
			{
				uint32_t i;
				reps[0] = prevOpt->backs[pos];
				for (i = 1; i <= pos; i++) reps[i] = prevOpt->backs[i - 1];
				for (; i < LZMA_NUM_REPS; i++) reps[i] = prevOpt->backs[i];
			}
			else
			{
				uint32_t i;
				reps[0] = (pos - LZMA_NUM_REPS);
				for (i = 1; i < LZMA_NUM_REPS; i++) reps[i] = prevOpt->backs[i - 1];
			}
		}
		curOpt->state = (CState)state;
		curOpt->backs[0] = reps[0];
		curOpt->backs[1] = reps[1];
		curOpt->backs[2] = reps[2];
		curOpt->backs[3] = reps[3];
		curPrice = curOpt->price;
		nextIsChar = 0;
		data = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - 1;
		curByte = *data;
		matchByte = *(data - (reps[0] + 1));
		posState = (position & p->pbMask);
		curAnd1Price = curPrice + GET_PRICE_0(p->isMatch[state][posState]);
		{
			const uint16_t *probs = LIT_PROBS(position, *(data - 1));
			curAnd1Price +=
			(!IsCharState(state) ?
			 LitEnc_GetPriceMatched(probs, curByte, matchByte, p->ProbPrices) :
			 LitEnc_GetPrice(probs, curByte, p->ProbPrices));
		}
		nextOpt = &p->opt[cur + 1];
		if (curAnd1Price < nextOpt->price)
		{
			nextOpt->price = curAnd1Price;
			nextOpt->posPrev = cur;
			MakeAsChar(nextOpt);
			nextIsChar = 1;
		}
		matchPrice = curPrice + GET_PRICE_1(p->isMatch[state][posState]);
		repMatchPrice = matchPrice + GET_PRICE_1(p->isRep[state]);
		if (matchByte == curByte && !(nextOpt->posPrev < cur && nextOpt->backPrev == 0))
		{
			uint32_t shortRepPrice = repMatchPrice + GetRepLen1Price(p, state, posState);
			if (shortRepPrice <= nextOpt->price)
			{
				nextOpt->price = shortRepPrice;
				nextOpt->posPrev = cur;
				MakeAsShortRep(nextOpt);
				nextIsChar = 1;
			}
		}
		numAvailFull = p->numAvail;
		{
			uint32_t temp = kNumOpts - 1 - cur;
			if (temp < numAvailFull) numAvailFull = temp;
		}
		if (numAvailFull < 2) continue;
		numAvail = (numAvailFull <= p->numFastBytes ? numAvailFull : p->numFastBytes);
		if (!nextIsChar && matchByte != curByte)
		{
			uint32_t temp;
			uint32_t lenTest2;
			const uint8_t *data2 = data - reps[0] - 1;
			uint32_t limit = p->numFastBytes + 1;
			if (limit > numAvailFull) limit = numAvailFull;
			for (temp = 1; temp < limit && data[temp] == data2[temp]; temp++);
			lenTest2 = temp - 1;
			if (lenTest2 >= 2)
			{
				uint32_t state2 = kLiteralNextStates[state];
				uint32_t posStateNext = (position + 1) & p->pbMask;
				uint32_t nextRepMatchPrice = curAnd1Price +
				GET_PRICE_1(p->isMatch[state2][posStateNext]) +
				GET_PRICE_1(p->isRep[state2]);
				{
					uint32_t curAndLenPrice;
					COptimal *opt;
					uint32_t offset = cur + 1 + lenTest2;
					while (lenEnd < offset) p->opt[++lenEnd].price = kInfinityPrice;
					curAndLenPrice = nextRepMatchPrice + GetRepPrice(p, 0, lenTest2, state2, posStateNext);
					opt = &p->opt[offset];
					if (curAndLenPrice < opt->price)
					{
						opt->price = curAndLenPrice;
						opt->posPrev = cur + 1;
						opt->backPrev = 0;
						opt->prev1IsChar = 1;
						opt->prev2 = 0;
					}
				}
			}
		}
		startLen = 2;
		{
			uint32_t repIndex;
			for (repIndex = 0; repIndex < LZMA_NUM_REPS; repIndex++)
			{
				uint32_t lenTest;
				uint32_t lenTestTemp;
				uint32_t price;
				const uint8_t *data2 = data - reps[repIndex] - 1;
				if (data[0] != data2[0] || data[1] != data2[1]) continue;
				for (lenTest = 2; lenTest < numAvail && data[lenTest] == data2[lenTest]; lenTest++);
				while (lenEnd < cur + lenTest) p->opt[++lenEnd].price = kInfinityPrice;
				lenTestTemp = lenTest;
				price = repMatchPrice + GetPureRepPrice(p, repIndex, state, posState);
				do {
					uint32_t curAndLenPrice = price + p->repLenEnc.prices[posState][lenTest - 2];
					COptimal *opt = &p->opt[cur + lenTest];
					if (curAndLenPrice < opt->price)
					{
						opt->price = curAndLenPrice;
						opt->posPrev = cur;
						opt->backPrev = repIndex;
						opt->prev1IsChar = 0;
					}
				} while (--lenTest >= 2);
				lenTest = lenTestTemp;
				if (repIndex == 0) startLen = lenTest + 1;

				{
					uint32_t lenTest2 = lenTest + 1;
					uint32_t limit = lenTest2 + p->numFastBytes;
					uint32_t nextRepMatchPrice;
					if (limit > numAvailFull) limit = numAvailFull;
					for (; lenTest2 < limit && data[lenTest2] == data2[lenTest2]; lenTest2++);
					lenTest2 -= lenTest + 1;
					if (lenTest2 >= 2)
					{
						uint32_t state2 = kRepNextStates[state];
						uint32_t posStateNext = (position + lenTest) & p->pbMask;
						uint32_t curAndLenCharPrice =
						price + p->repLenEnc.prices[posState][lenTest - 2] +
						GET_PRICE_0(p->isMatch[state2][posStateNext]) +
						LitEnc_GetPriceMatched(LIT_PROBS(position + lenTest, data[lenTest - 1]),
											   data[lenTest], data2[lenTest], p->ProbPrices);
						state2 = kLiteralNextStates[state2];
						posStateNext = (position + lenTest + 1) & p->pbMask;
						nextRepMatchPrice = curAndLenCharPrice +
						GET_PRICE_1(p->isMatch[state2][posStateNext]) +
						GET_PRICE_1(p->isRep[state2]);

						{
							uint32_t curAndLenPrice;
							COptimal *opt;
							uint32_t offset = cur + lenTest + 1 + lenTest2;
							while (lenEnd < offset)
								p->opt[++lenEnd].price = kInfinityPrice;
							curAndLenPrice = nextRepMatchPrice + GetRepPrice(p, 0, lenTest2, state2, posStateNext);
							opt = &p->opt[offset];
							if (curAndLenPrice < opt->price)
							{
								opt->price = curAndLenPrice;
								opt->posPrev = cur + lenTest + 1;
								opt->backPrev = 0;
								opt->prev1IsChar = 1;
								opt->prev2 = 1;
								opt->posPrev2 = cur;
								opt->backPrev2 = repIndex;
							}
						}
					}
				}
			}
		}
		if (newLen > numAvail)
		{
			newLen = numAvail;
			for (numPairs = 0; newLen > matches[numPairs]; numPairs += 2);
			matches[numPairs] = newLen;
			numPairs += 2;
		}
		if (newLen >= startLen)
		{
			uint32_t normalMatchPrice = matchPrice + GET_PRICE_0(p->isRep[state]);
			uint32_t offs, curBack, posSlot;
			uint32_t lenTest;
			while (lenEnd < cur + newLen) p->opt[++lenEnd].price = kInfinityPrice;
			offs = 0;
			while (startLen > matches[offs]) offs += 2;
			curBack = matches[offs + 1];
			GetPosSlot2(curBack, posSlot);
			for (lenTest = startLen; ; lenTest++)
			{
				uint32_t curAndLenPrice = normalMatchPrice + p->lenEnc.prices[posState][lenTest - LZMA_MATCH_LEN_MIN];
				uint32_t lenToPosState = GetLenToPosState(lenTest);
				COptimal *opt;
				if (curBack < kNumFullDistances) curAndLenPrice += p->distancesPrices[lenToPosState][curBack];
				else curAndLenPrice += p->posSlotPrices[lenToPosState][posSlot] + p->alignPrices[curBack & kAlignMask];
				opt = &p->opt[cur + lenTest];
				if (curAndLenPrice < opt->price)
				{
					opt->price = curAndLenPrice;
					opt->posPrev = cur;
					opt->backPrev = curBack + LZMA_NUM_REPS;
					opt->prev1IsChar = 0;
				}
				if (lenTest == matches[offs])
				{
					const uint8_t *data2 = data - curBack - 1;
					uint32_t lenTest2 = lenTest + 1;
					uint32_t limit = lenTest2 + p->numFastBytes;
					uint32_t nextRepMatchPrice;
					if (limit > numAvailFull) limit = numAvailFull;
					for (; lenTest2 < limit && data[lenTest2] == data2[lenTest2]; lenTest2++);
					lenTest2 -= lenTest + 1;
					if (lenTest2 >= 2)
					{
						uint32_t state2 = kMatchNextStates[state];
						uint32_t posStateNext = (position + lenTest) & p->pbMask;
						uint32_t curAndLenCharPrice = curAndLenPrice +
						GET_PRICE_0(p->isMatch[state2][posStateNext]) +
						LitEnc_GetPriceMatched(LIT_PROBS(position + lenTest, data[lenTest - 1]),
											   data[lenTest], data2[lenTest], p->ProbPrices);
						state2 = kLiteralNextStates[state2];
						posStateNext = (posStateNext + 1) & p->pbMask;
						nextRepMatchPrice = curAndLenCharPrice +
						GET_PRICE_1(p->isMatch[state2][posStateNext]) +
						GET_PRICE_1(p->isRep[state2]);

						{
							uint32_t offset = cur + lenTest + 1 + lenTest2;
							uint32_t curAndLenPrice;
							COptimal *opt;
							while (lenEnd < offset) p->opt[++lenEnd].price = kInfinityPrice;
							curAndLenPrice = nextRepMatchPrice + GetRepPrice(p, 0, lenTest2, state2, posStateNext);
							opt = &p->opt[offset];
							if (curAndLenPrice < opt->price)
							{
								opt->price = curAndLenPrice;
								opt->posPrev = cur + lenTest + 1;
								opt->backPrev = 0;
								opt->prev1IsChar = 1;
								opt->prev2 = 1;
								opt->posPrev2 = cur;
								opt->backPrev2 = curBack + LZMA_NUM_REPS;
							}
						}
					}
					offs += 2;
					if (offs == numPairs) break;
					curBack = matches[offs + 1];
					if (curBack >= kNumFullDistances) { GetPosSlot2(curBack, posSlot); }
				}
			}
		}
	}
}
static void LitEnc_EncodeMatched(CRangeEnc *p, uint16_t *probs, uint32_t symbol, uint32_t matchByte) {
	uint32_t offs = 0x100;
	symbol |= 0x100;
	do {
		matchByte <<= 1;
		RangeEnc_EncodeBit(p, probs + (offs + (matchByte & offs) + (symbol >> 8)), (symbol >> 7) & 1);
		symbol <<= 1;
		offs &= ~(matchByte ^ symbol);
	} while (symbol < 0x10000);
}

static int LzmaEnc_CodeOneBlock(CLzmaEnc *p, uint8_t useLimits, uint32_t maxPackSize, uint32_t maxUnpackSize) {
	const int kLiteralNextStates[kNumStates] = {0, 0, 0, 0, 1, 2, 3, 4,  5,  6, 4, 5};
	const int kMatchNextStates[kNumStates]   = {7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10};
	const int kRepNextStates[kNumStates]     = {8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11};
	const int kShortRepNextStates[kNumStates]= {9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11};
	uint32_t nowPos32, startPos32;
	if (p->needInit)
	{
		p->matchFinder.Init(p->matchFinderObj);
		p->needInit = 0;
	}
	if (p->finished) return p->result;
	RINOK(CheckErrors(p));
	nowPos32 = (uint32_t)p->nowPos64;
	startPos32 = nowPos32;
	if (p->nowPos64 == 0)
	{
		uint32_t numPairs;
		uint8_t curByte;
		if (p->matchFinder.GetNumAvailableBytes(p->matchFinderObj) == 0) return Flush(p, nowPos32);
		ReadMatchDistances(p, &numPairs);
		RangeEnc_EncodeBit(&p->rc, &p->isMatch[p->state][0], 0);
		p->state = kLiteralNextStates[p->state];
		curByte = *(p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - p->additionalOffset);
		LitEnc_Encode(&p->rc, p->litProbs, curByte);
		p->additionalOffset--;
		nowPos32++;
	}
	if (p->matchFinder.GetNumAvailableBytes(p->matchFinderObj) != 0)
		for (;;)
		{
	  uint32_t pos, len, posState;

	  if (p->fastMode) len = GetOptimumFast(p, &pos);
	  else len = GetOptimum(p, nowPos32, &pos);

	  posState = nowPos32 & p->pbMask;
	  if (len == 1 && pos == (uint32_t)-1)
	  {
		  uint8_t curByte;
		  uint16_t *probs;
		  const uint8_t *data;

		  RangeEnc_EncodeBit(&p->rc, &p->isMatch[p->state][posState], 0);
		  data = p->matchFinder.GetPointerToCurrentPos(p->matchFinderObj) - p->additionalOffset;
		  curByte = *data;
		  probs = LIT_PROBS(nowPos32, *(data - 1));
		  if (IsCharState(p->state)) LitEnc_Encode(&p->rc, probs, curByte);
		  else LitEnc_EncodeMatched(&p->rc, probs, curByte, *(data - p->reps[0] - 1));
		  p->state = kLiteralNextStates[p->state];
	  }
	  else
	  {
		  RangeEnc_EncodeBit(&p->rc, &p->isMatch[p->state][posState], 1);
		  if (pos < LZMA_NUM_REPS)
		  {
			  RangeEnc_EncodeBit(&p->rc, &p->isRep[p->state], 1);
			  if (pos == 0)
			  {
				  RangeEnc_EncodeBit(&p->rc, &p->isRepG0[p->state], 0);
				  RangeEnc_EncodeBit(&p->rc, &p->isRep0Long[p->state][posState], ((len == 1) ? 0 : 1));
			  }
			  else
			  {
				  uint32_t distance = p->reps[pos];
				  RangeEnc_EncodeBit(&p->rc, &p->isRepG0[p->state], 1);
				  if (pos == 1) RangeEnc_EncodeBit(&p->rc, &p->isRepG1[p->state], 0);
				  else
				  {
					  RangeEnc_EncodeBit(&p->rc, &p->isRepG1[p->state], 1);
					  RangeEnc_EncodeBit(&p->rc, &p->isRepG2[p->state], pos - 2);
					  if (pos == 3) p->reps[3] = p->reps[2];
					  p->reps[2] = p->reps[1];
				  }
				  p->reps[1] = p->reps[0];
				  p->reps[0] = distance;
			  }
			  if (len == 1) p->state = kShortRepNextStates[p->state];
			  else
			  {
				  LenEnc_Encode2(&p->repLenEnc, &p->rc, len - LZMA_MATCH_LEN_MIN, posState, !p->fastMode, p->ProbPrices);
				  p->state = kRepNextStates[p->state];
			  }
		  }
		  else
		  {
			  uint32_t posSlot;
			  RangeEnc_EncodeBit(&p->rc, &p->isRep[p->state], 0);
			  p->state = kMatchNextStates[p->state];
			  LenEnc_Encode2(&p->lenEnc, &p->rc, len - LZMA_MATCH_LEN_MIN, posState, !p->fastMode, p->ProbPrices);
			  pos -= LZMA_NUM_REPS;
			  GetPosSlot(pos, posSlot);
			  RcTree_Encode(&p->rc, p->posSlotEncoder[GetLenToPosState(len)], kNumPosSlotBits, posSlot);

			  if (posSlot >= kStartPosModelIndex)
			  {
				  uint32_t footerBits = ((posSlot >> 1) - 1);
				  uint32_t base = ((2 | (posSlot & 1)) << footerBits);
				  uint32_t posReduced = pos - base;

				  if (posSlot < kEndPosModelIndex)
					  RcTree_ReverseEncode(&p->rc, p->posEncoders + base - posSlot - 1, footerBits, posReduced);
				  else
				  {
					  RangeEnc_EncodeDirectBits(&p->rc, posReduced >> kNumAlignBits, footerBits - kNumAlignBits);
					  RcTree_ReverseEncode(&p->rc, p->posAlignEncoder, kNumAlignBits, posReduced & kAlignMask);
					  p->alignPriceCount++;
				  }
			  }
			  p->reps[3] = p->reps[2];
			  p->reps[2] = p->reps[1];
			  p->reps[1] = p->reps[0];
			  p->reps[0] = pos;
			  p->matchPriceCount++;
		  }
	  }
	  p->additionalOffset -= len;
	  nowPos32 += len;
	  if (p->additionalOffset == 0)
	  {
		  uint32_t processed;
		  if (!p->fastMode)
		  {
			  if (p->matchPriceCount >= (1 << 7)) FillDistancesPrices(p);
			  if (p->alignPriceCount >= kAlignTableSize) FillAlignPrices(p);
		  }
		  if (p->matchFinder.GetNumAvailableBytes(p->matchFinderObj) == 0) break;
		  processed = nowPos32 - startPos32;
		  if (useLimits)
		  {
			  if (processed + kNumOpts + 300 >= maxUnpackSize ||
				  RangeEnc_GetProcessed(&p->rc) + kNumOpts * 2 >= maxPackSize)
				  break;
		  }
		  else if (processed >= (1 << 17))
		  {
			  p->nowPos64 += nowPos32 - startPos32;
			  return CheckErrors(p);
		  }
	  }
  }
	p->nowPos64 += nowPos32 - startPos32;
	return Flush(p, nowPos32);
}
static void LzmaEnc_Finish(CLzmaEncHandle pp) { }
static int LzmaEnc_Encode2(CLzmaEnc *p, ICompressProgress *progress)
{
	int res = SZ_OK;
	for (;;)
	{
		res = LzmaEnc_CodeOneBlock(p, 0, 0, 0);
		if (res != SZ_OK || p->finished != 0) break;
		if (progress != 0)
		{
			res = progress->Progress(progress, p->nowPos64, RangeEnc_GetProcessed(&p->rc));
			if (res != SZ_OK)
			{
				res = SZ_ERROR_PROGRESS;
				break;
			}
		}
	}
	LzmaEnc_Finish(p);
	return res;
}

static int LzmaEnc_MemEncode(CLzmaEncHandle pp, uint8_t *dest, size_t *destLen, const uint8_t *src, size_t srcLen,
							 int writeEndMark, ICompressProgress *progress, ISzAlloc *alloc, ISzAlloc *allocBig) {
	CLzmaEnc *p = (CLzmaEnc *)pp;
	CSeqOutStreamBuf outStream;
	LzmaEnc_SetInputBuf(p, src, srcLen);
	outStream.funcTable.Write = MyWrite;
	outStream.data = dest;
	outStream.rem = *destLen;
	outStream.overflow = 0;
	p->writeEndMark = writeEndMark;
	p->rc.outStream = &outStream.funcTable;
	int res = LzmaEnc_MemPrepare(pp, src, srcLen, 0, alloc, allocBig);
	if (res == SZ_OK) res = LzmaEnc_Encode2(p, progress);
	*destLen -= outStream.rem;
	if (outStream.overflow) return SZ_ERROR_OUTPUT_EOF;
	return res;
}

static void LzmaEnc_Destruct(CLzmaEnc *p, ISzAlloc *alloc, ISzAlloc *allocBig) {
	MatchFinder_Free(&p->matchFinderBase, allocBig);
	LzmaEnc_FreeLits(p, alloc);
	RangeEnc_Free(&p->rc, alloc);
}

static void LzmaEnc_Destroy(CLzmaEncHandle p, ISzAlloc *alloc, ISzAlloc *allocBig) {
	LzmaEnc_Destruct((CLzmaEnc *)p, alloc, allocBig);
	alloc->Free(alloc, p);
}

static int LzmaEncode(uint8_t *dest, size_t *destLen, const uint8_t *src, size_t srcLen,
					  const CLzmaEncProps *props, uint8_t *propsEncoded, size_t *propsSize, int writeEndMark,
					  ICompressProgress *progress, ISzAlloc *alloc, ISzAlloc *allocBig) {
	CLzmaEnc *p = (CLzmaEnc *)LzmaEnc_Create(alloc);
	if (p == 0) return SZ_ERROR_MEM;

	int res = LzmaEnc_SetProps(p, props);
	if (res == SZ_OK)
	{
		res = LzmaEnc_WriteProperties(p, propsEncoded, propsSize);
		if (res == SZ_OK)
			res = LzmaEnc_MemEncode(p, dest, destLen, src, srcLen,
									writeEndMark, progress, alloc, allocBig);
	}

	LzmaEnc_Destroy(p, alloc, allocBig);
	return res;
}

static void *MyAlloc(size_t size) {
	if (size == 0) return 0;
	return malloc(size);
}

static void MyFree(void *address) { free(address); }
static void *SzAlloc(void *p, size_t size) { return MyAlloc(size); }
static void SzFree(void *p, void *address) { MyFree(address); }
static int LzmaCompress(uint8_t *dest, size_t *destLen, const uint8_t *src, size_t srcLen,
						uint8_t *outProps, size_t *outPropsSize,
						int level, /* 0 <= level <= 9, default = 5 */
						unsigned dictSize, /* use (1 << N) or (3 << N). 4 KB < dictSize <= 128 MB */
						int lc, /* 0 <= lc <= 8, default = 3  */
						int lp, /* 0 <= lp <= 4, default = 0  */
						int pb, /* 0 <= pb <= 4, default = 2  */
						int fb,  /* 5 <= fb <= 273, default = 32 */
						int numThreads /* 1 or 2, default = 2 */
) {
	CLzmaEncProps props;
	LzmaEncProps_Init(&props);
	props.level = level;
	props.dictSize = dictSize;
	props.lc = lc;
	props.lp = lp;
	props.pb = pb;
	props.fb = fb;
	props.numThreads = numThreads;
	ISzAlloc g_Alloc = { SzAlloc, SzFree };
	return LzmaEncode(dest, destLen, src, srcLen, &props, outProps, outPropsSize, 0,
					  NULL, &g_Alloc, &g_Alloc);
}


/**
 @brief Get lzma compressed data with compression ratio.
 @param dataToCompress The data for compress.
 @param compressionRatio Float compression ratio value in range [0.0f; 1.0f].
 @return Lzma compressed data or nil on error or dataToCompress is empty.
 */
NS_INLINE NSData * NSDataGetLzmaCompressDataWithRatio(NSData * dataToCompress, const CGFloat compressionRatio)
{
	if (!dataToCompress) return nil;

#if defined(DEBUG)
	assert([dataToCompress isKindOfClass:[NSData class]]);
#endif

	if ([dataToCompress length] == 0) return nil;

	uint32_t outSize = (uint32_t)(((size_t)[dataToCompress length] / 20) * 21) + (1 << 16);
	if (outSize == 0) return nil;

	size_t destLen = outSize;
	outSize += (LZMA_PROPS_SIZE + sizeof(uint32_t));
	uint8_t * compressedBuffer = (uint8_t *)malloc(outSize);
	if (!compressedBuffer) return nil;

	int level = 0;
	if (compressionRatio < 0.0f)
	{
		level = 0;
	}
	else if (compressionRatio > 1.0f)
	{
		level = 9;
	}
	else
	{
		level = (int)(compressionRatio * 9.0f);
	}


	uint8_t * sizePtr = (uint8_t *)compressedBuffer;
	uint8_t * props = sizePtr + sizeof(uint32_t);
	uint8_t * dest = props + LZMA_PROPS_SIZE;
	size_t outPropsSize = LZMA_PROPS_SIZE;
	const int comprResult = LzmaCompress(dest,
										 &destLen,
										 (const uint8_t *)[dataToCompress bytes],
										 (size_t)[dataToCompress length],
										 props,
										 &outPropsSize,
										 level, // compr
										 1 << 24,
										 3,
										 0,
										 2,
										 32,
										 1);
	if (comprResult == SZ_OK)
	{
		uint32_t * int32Ptr = (uint32_t *)sizePtr;
		*int32Ptr = (uint32_t)[dataToCompress length];
		NSData * d = [NSData dataWithBytesNoCopy:compressedBuffer
										  length:(uint32_t)destLen + LZMA_PROPS_SIZE + sizeof(uint32_t)
							  freeWhenDone:YES];
		if (d) return d;
	}
	free(compressedBuffer);
	return nil;
}

typedef enum {
	LZMA_STATUS_NOT_SPECIFIED,
	LZMA_STATUS_FINISHED_WITH_MARK,
	LZMA_STATUS_NOT_FINISHED,
	LZMA_STATUS_NEEDS_MORE_INPUT,
	LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
} ELzmaStatus;

typedef enum {
	LZMA_FINISH_ANY,
	LZMA_FINISH_END
} ELzmaFinishMode;

typedef struct _CLzmaProps {
	unsigned lc, lp, pb;
	uint32_t dicSize;
} CLzmaProps;

#define LZMA_REQUIRED_INPUT_MAX 20
#define RC_INIT_SIZE 5

typedef struct {
	CLzmaProps prop;
	uint16_t *probs;
	uint8_t *dic;
	const uint8_t *buf;
	uint32_t range, code;
	size_t dicPos;
	size_t dicBufSize;
	uint32_t processedPos;
	uint32_t checkDicSize;
	unsigned state;
	uint32_t reps[4];
	unsigned remainLen;
	int needFlush;
	int needInitState;
	uint32_t numProbs;
	unsigned tempBufSize;
	uint8_t tempBuf[LZMA_REQUIRED_INPUT_MAX];
} CLzmaDec;

#define LzmaDec_Construct(p) { (p)->dic = 0; (p)->probs = 0; }
#define LZMA_DIC_MIN (1 << 12)

static int LzmaProps_Decode(CLzmaProps *p, const uint8_t *data, unsigned size) {
	uint32_t dicSize;
	uint8_t d;
	if (size < LZMA_PROPS_SIZE) return SZ_ERROR_UNSUPPORTED;
	else dicSize = data[1] | ((uint32_t)data[2] << 8) | ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 24);
	if (dicSize < LZMA_DIC_MIN) dicSize = LZMA_DIC_MIN;
	p->dicSize = dicSize;
	d = data[0];
	if (d >= (9 * 5 * 5)) return SZ_ERROR_UNSUPPORTED;
	p->lc = d % 9;
	d /= 9;
	p->pb = d / 5;
	p->lp = d % 5;
	return SZ_OK;
}

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE 0x300
#define kNumPosBitsMax 4
#define kNumPosStatesMax (1 << kNumPosBitsMax)
#define LenChoice 0
#define LenChoice2 (LenChoice + 1)
#define LenLow (LenChoice2 + 1)
#define LenMid (LenLow + (kNumPosStatesMax << kLenNumLowBits))
#define LenHigh (LenMid + (kNumPosStatesMax << kLenNumMidBits))
#define kNumLenProbs (LenHigh + kLenNumHighSymbols)
#define IsMatch 0
#define IsRep (IsMatch + (kNumStates << kNumPosBitsMax))
#define IsRepG0 (IsRep + kNumStates)
#define IsRepG1 (IsRepG0 + kNumStates)
#define IsRepG2 (IsRepG1 + kNumStates)
#define IsRep0Long (IsRepG2 + kNumStates)
#define PosSlot (IsRep0Long + (kNumStates << kNumPosBitsMax))
#define SpecPos (PosSlot + (kNumLenToPosStates << kNumPosSlotBits))
#define Align (SpecPos + kNumFullDistances - kEndPosModelIndex)
#define LenCoder (Align + kAlignTableSize)
#define RepLenCoder (LenCoder + kNumLenProbs)
#define Literal (RepLenCoder + kNumLenProbs)
#define LzmaProps_GetNumProbs(p) (Literal + ((uint32_t)LZMA_LIT_SIZE << ((p)->lc + (p)->lp)))

static void LzmaDec_FreeProbs(CLzmaDec *p, ISzAlloc *alloc) {
	alloc->Free(alloc, p->probs);
	p->probs = NULL;
}

static int LzmaDec_AllocateProbs2(CLzmaDec *p, const CLzmaProps *propNew, ISzAlloc *alloc) {
	uint32_t numProbs = LzmaProps_GetNumProbs(propNew);
	if (!p->probs || numProbs != p->numProbs)
	{
		LzmaDec_FreeProbs(p, alloc);
		p->probs = (uint16_t *)alloc->Alloc(alloc, numProbs * sizeof(uint16_t));
		p->numProbs = numProbs;
		if (!p->probs) return SZ_ERROR_MEM;
	}
	return SZ_OK;
}

static int LzmaDec_AllocateProbs(CLzmaDec *p, const uint8_t *props, unsigned propsSize, ISzAlloc *alloc) {
	CLzmaProps propNew;
	RINOK(LzmaProps_Decode(&propNew, props, propsSize));
	RINOK(LzmaDec_AllocateProbs2(p, &propNew, alloc));
	p->prop = propNew;
	return SZ_OK;
}

static void LzmaDec_InitDicAndState(CLzmaDec *p, uint8_t initDic, uint8_t initState) {
	p->needFlush = 1;
	p->remainLen = 0;
	p->tempBufSize = 0;
	if (initDic)
	{
		p->processedPos = 0;
		p->checkDicSize = 0;
		p->needInitState = 1;
	}
	if (initState) p->needInitState = 1;
}

static void LzmaDec_Init(CLzmaDec *p) {
	p->dicPos = 0;
	LzmaDec_InitDicAndState(p, 1, 1);
}

#define kMatchMinLen 2
#define kMatchSpecLenStart (kMatchMinLen + kLenNumLowSymbols + kLenNumMidSymbols + kLenNumHighSymbols)

static void LzmaDec_WriteRem(CLzmaDec *p, size_t limit) {
	if (p->remainLen != 0 && p->remainLen < kMatchSpecLenStart)
	{
		uint8_t *dic = p->dic;
		size_t dicPos = p->dicPos;
		size_t dicBufSize = p->dicBufSize;
		unsigned len = p->remainLen;
		size_t rep0 = p->reps[0];
		size_t rem = limit - dicPos;
		if (rem < len) len = (unsigned)(rem);
		if (p->checkDicSize == 0 && p->prop.dicSize - p->processedPos <= len) p->checkDicSize = p->prop.dicSize;
		p->processedPos += len;
		p->remainLen -= len;
		while (len != 0)
		{
			len--;
			dic[dicPos] = dic[dicPos - rep0 + (dicPos < rep0 ? dicBufSize : 0)];
			dicPos++;
		}
		p->dicPos = dicPos;
	}
}

#define LzmaProps_GetNumProbs(p) (Literal + ((uint32_t)LZMA_LIT_SIZE << ((p)->lc + (p)->lp)))

static void LzmaDec_InitStateReal(CLzmaDec *p) {
	size_t numProbs = LzmaProps_GetNumProbs(&p->prop);
	size_t i;
	uint16_t *probs = p->probs;
	for (i = 0; i < numProbs; i++) probs[i] = kBitModelTotal >> 1;
	p->reps[0] = p->reps[1] = p->reps[2] = p->reps[3] = 1;
	p->state = 0;
	p->needInitState = 0;
}

typedef enum {
	DUMMY_ERROR,
	DUMMY_LIT,
	DUMMY_MATCH,
	DUMMY_REP
} ELzmaDummy;

#define NORMALIZE_CHECK if (range < kTopValue) { if (buf >= bufLimit) return DUMMY_ERROR; range <<= 8; code = (code << 8) | (*buf++); }
#define IF_BIT_0_CHECK(p) ttt = *(p); NORMALIZE_CHECK; bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0_CHECK range = bound;
#define UPDATE_1_CHECK range -= bound; code -= bound;
#define GET_BIT2_CHECK(p, i, A0, A1) IF_BIT_0_CHECK(p) \
{ UPDATE_0_CHECK; i = (i + i); A0; } else \
{ UPDATE_1_CHECK; i = (i + i) + 1; A1; }
#define GET_BIT_CHECK(p, i) GET_BIT2_CHECK(p, i, ; , ;)
#define TREE_DECODE_CHECK(probs, limit, i) \
{ i = 1; do { GET_BIT_CHECK(probs + i, i) } while (i < limit); i -= limit; }

#define kNumLitStates 7

static ELzmaDummy LzmaDec_TryDummy(const CLzmaDec *p, const uint8_t *buf, size_t inSize) {
	uint32_t range = p->range;
	uint32_t code = p->code;
	const uint8_t *bufLimit = buf + inSize;
	const uint16_t *probs = p->probs;
	unsigned state = p->state;
	ELzmaDummy res;
	{
		const uint16_t *prob;
		uint32_t bound;
		unsigned ttt;
		unsigned posState = (p->processedPos) & ((1 << p->prop.pb) - 1);

		prob = probs + IsMatch + (state << kNumPosBitsMax) + posState;
		IF_BIT_0_CHECK(prob)
		{
			UPDATE_0_CHECK
			prob = probs + Literal;
			if (p->checkDicSize != 0 || p->processedPos != 0)
				prob += ((uint32_t)LZMA_LIT_SIZE *
						 ((((p->processedPos) & ((1 << (p->prop.lp)) - 1)) << p->prop.lc) +
						  (p->dic[(p->dicPos == 0 ? p->dicBufSize : p->dicPos) - 1] >> (8 - p->prop.lc))));

			if (state < kNumLitStates)
			{
				unsigned symbol = 1;
				do { GET_BIT_CHECK(prob + symbol, symbol) } while (symbol < 0x100);
			}
			else
			{
				unsigned matchByte = p->dic[p->dicPos - p->reps[0] +
											(p->dicPos < p->reps[0] ? p->dicBufSize : 0)];
				unsigned offs = 0x100;
				unsigned symbol = 1;
				do {
					unsigned bit;
					const uint16_t *probLit;
					matchByte <<= 1;
					bit = (matchByte & offs);
					probLit = prob + offs + bit + symbol;
					GET_BIT2_CHECK(probLit, symbol, offs &= ~bit, offs &= bit)
				} while (symbol < 0x100);
			}
			res = DUMMY_LIT;
		}
		else
		{
			unsigned len;
			UPDATE_1_CHECK;

			prob = probs + IsRep + state;
			IF_BIT_0_CHECK(prob)
			{
				UPDATE_0_CHECK;
				state = 0;
				prob = probs + LenCoder;
				res = DUMMY_MATCH;
			}
			else
			{
				UPDATE_1_CHECK;
				res = DUMMY_REP;
				prob = probs + IsRepG0 + state;
				IF_BIT_0_CHECK(prob)
				{
					UPDATE_0_CHECK;
					prob = probs + IsRep0Long + (state << kNumPosBitsMax) + posState;
					IF_BIT_0_CHECK(prob)
					{
						UPDATE_0_CHECK;
						NORMALIZE_CHECK;
						return DUMMY_REP;
					}
					else
					{
						UPDATE_1_CHECK;
					}
				}
				else
				{
					UPDATE_1_CHECK;
					prob = probs + IsRepG1 + state;
					IF_BIT_0_CHECK(prob)
					{
						UPDATE_0_CHECK;
					}
					else
					{
						UPDATE_1_CHECK;
						prob = probs + IsRepG2 + state;
						IF_BIT_0_CHECK(prob)
						{
							UPDATE_0_CHECK;
						}
						else
						{
							UPDATE_1_CHECK;
						}
					}
				}
				state = kNumStates;
				prob = probs + RepLenCoder;
			}
			{
				unsigned limit, offset;
				const uint16_t *probLen = prob + LenChoice;
				IF_BIT_0_CHECK(probLen)
				{
					UPDATE_0_CHECK;
					probLen = prob + LenLow + (posState << kLenNumLowBits);
					offset = 0;
					limit = 1 << kLenNumLowBits;
				}
				else
				{
					UPDATE_1_CHECK;
					probLen = prob + LenChoice2;
					IF_BIT_0_CHECK(probLen)
					{
						UPDATE_0_CHECK;
						probLen = prob + LenMid + (posState << kLenNumMidBits);
						offset = kLenNumLowSymbols;
						limit = 1 << kLenNumMidBits;
					}
					else
					{
						UPDATE_1_CHECK;
						probLen = prob + LenHigh;
						offset = kLenNumLowSymbols + kLenNumMidSymbols;
						limit = 1 << kLenNumHighBits;
					}
				}
				TREE_DECODE_CHECK(probLen, limit, len);
				len += offset;
			}
			if (state < 4)
			{
				unsigned posSlot;
				prob = probs + PosSlot +
				((len < kNumLenToPosStates ? len : kNumLenToPosStates - 1) <<
				 kNumPosSlotBits);
				TREE_DECODE_CHECK(prob, 1 << kNumPosSlotBits, posSlot);
				if (posSlot >= kStartPosModelIndex)
				{
					unsigned numDirectBits = ((posSlot >> 1) - 1);
					if (posSlot < kEndPosModelIndex)
					{
						prob = probs + SpecPos + ((2 | (posSlot & 1)) << numDirectBits) - posSlot - 1;
					}
					else
					{
						numDirectBits -= kNumAlignBits;
						do {
							NORMALIZE_CHECK
							range >>= 1;
							code -= range & (((code - range) >> 31) - 1);
						} while (--numDirectBits != 0);
						prob = probs + Align;
						numDirectBits = kNumAlignBits;
					}
					{
						unsigned i = 1;
						do {
							GET_BIT_CHECK(prob + i, i);
						} while (--numDirectBits != 0);
					}
				}
			}
		}
	}
	NORMALIZE_CHECK;
	return res;
}

#define NORMALIZE if (range < kTopValue) { range <<= 8; code = (code << 8) | (*buf++); }
#define IF_BIT_0(p) ttt = *(p); NORMALIZE; bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0(p) range = bound; *(p) = (uint16_t)(ttt + ((kBitModelTotal - ttt) >> kNumMoveBits));
#define UPDATE_1(p) range -= bound; code -= bound; *(p) = (uint16_t)(ttt - (ttt >> kNumMoveBits));
#define GET_BIT2(p, i, A0, A1) IF_BIT_0(p) \
{ UPDATE_0(p); i = (i + i); A0; } else \
{ UPDATE_1(p); i = (i + i) + 1; A1; }
#define GET_BIT(p, i) GET_BIT2(p, i, ; , ;)
#define NORMAL_LITER_DEC GET_BIT(prob + symbol, symbol)
#define NORMAL_LITER_DEC GET_BIT(prob + symbol, symbol)
#define MATCHED_LITER_DEC \
matchByte <<= 1; \
bit = (matchByte & offs); \
probLit = prob + offs + bit + symbol; \
GET_BIT2(probLit, symbol, offs &= ~bit, offs &= bit)

#define TREE_GET_BIT(probs, i) { GET_BIT((probs + i), i); }
#define TREE_DECODE(probs, limit, i) \
{ i = 1; do { TREE_GET_BIT(probs, i); } while (i < limit); i -= limit; }

#define TREE_6_DECODE(probs, i) \
{ i = 1; \
	TREE_GET_BIT(probs, i); \
	TREE_GET_BIT(probs, i); \
	TREE_GET_BIT(probs, i); \
	TREE_GET_BIT(probs, i); \
	TREE_GET_BIT(probs, i); \
	TREE_GET_BIT(probs, i); \
	i -= 0x40; }

static int LzmaDec_DecodeReal(CLzmaDec *p, size_t limit, const uint8_t *bufLimit) {
	uint16_t *probs = p->probs;
	unsigned state = p->state;
	uint32_t rep0 = p->reps[0], rep1 = p->reps[1], rep2 = p->reps[2], rep3 = p->reps[3];
	unsigned pbMask = ((unsigned)1 << (p->prop.pb)) - 1;
	unsigned lpMask = ((unsigned)1 << (p->prop.lp)) - 1;
	unsigned lc = p->prop.lc;
	uint8_t *dic = p->dic;
	size_t dicBufSize = p->dicBufSize;
	size_t dicPos = p->dicPos;
	uint32_t processedPos = p->processedPos;
	uint32_t checkDicSize = p->checkDicSize;
	unsigned len = 0;
	const uint8_t *buf = p->buf;
	uint32_t range = p->range;
	uint32_t code = p->code;

	do {
		uint16_t *prob;
		uint32_t bound;
		unsigned ttt;
		unsigned posState = processedPos & pbMask;

		prob = probs + IsMatch + (state << kNumPosBitsMax) + posState;
		IF_BIT_0(prob)
		{
			unsigned symbol;
			UPDATE_0(prob);
			prob = probs + Literal;
			if (processedPos != 0 || checkDicSize != 0)
				prob += ((uint32_t)LZMA_LIT_SIZE * (((processedPos & lpMask) << lc) +
													(dic[(dicPos == 0 ? dicBufSize : dicPos) - 1] >> (8 - lc))));
			processedPos++;

			if (state < kNumLitStates)
			{
				state -= (state < 4) ? state : 3;
				symbol = 1;
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
				NORMAL_LITER_DEC
			}
			else
			{
				unsigned matchByte = dic[dicPos - rep0 + (dicPos < rep0 ? dicBufSize : 0)];
				unsigned offs = 0x100;
				state -= (state < 10) ? 3 : 6;
				symbol = 1;
				{
					unsigned bit;
					uint16_t *probLit;
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
					MATCHED_LITER_DEC
				}
			}

			dic[dicPos++] = (uint8_t)symbol;
			continue;
		}
		{
			UPDATE_1(prob);
			prob = probs + IsRep + state;
			IF_BIT_0(prob)
			{
				UPDATE_0(prob);
				state += kNumStates;
				prob = probs + LenCoder;
			}
			else
			{
				UPDATE_1(prob);
				if (checkDicSize == 0 && processedPos == 0) return SZ_ERROR_DATA;
				prob = probs + IsRepG0 + state;
				IF_BIT_0(prob)
				{
					UPDATE_0(prob);
					prob = probs + IsRep0Long + (state << kNumPosBitsMax) + posState;
					IF_BIT_0(prob)
					{
						UPDATE_0(prob);
						dic[dicPos] = dic[dicPos - rep0 + (dicPos < rep0 ? dicBufSize : 0)];
						dicPos++;
						processedPos++;
						state = state < kNumLitStates ? 9 : 11;
						continue;
					}
					UPDATE_1(prob);
				}
				else
				{
					uint32_t distance;
					UPDATE_1(prob);
					prob = probs + IsRepG1 + state;
					IF_BIT_0(prob)
					{
						UPDATE_0(prob);
						distance = rep1;
					}
					else
					{
						UPDATE_1(prob);
						prob = probs + IsRepG2 + state;
						IF_BIT_0(prob)
						{
							UPDATE_0(prob);
							distance = rep2;
						}
						else
						{
							UPDATE_1(prob);
							distance = rep3;
							rep3 = rep2;
						}
						rep2 = rep1;
					}
					rep1 = rep0;
					rep0 = distance;
				}
				state = state < kNumLitStates ? 8 : 11;
				prob = probs + RepLenCoder;
			}
			{
				uint16_t *probLen = prob + LenChoice;
				IF_BIT_0(probLen)
				{
					UPDATE_0(probLen);
					probLen = prob + LenLow + (posState << kLenNumLowBits);
					len = 1;
					TREE_GET_BIT(probLen, len);
					TREE_GET_BIT(probLen, len);
					TREE_GET_BIT(probLen, len);
					len -= 8;
				}
				else
				{
					UPDATE_1(probLen);
					probLen = prob + LenChoice2;
					IF_BIT_0(probLen)
					{
						UPDATE_0(probLen);
						probLen = prob + LenMid + (posState << kLenNumMidBits);
						len = 1;
						TREE_GET_BIT(probLen, len);
						TREE_GET_BIT(probLen, len);
						TREE_GET_BIT(probLen, len);
					}
					else
					{
						UPDATE_1(probLen);
						probLen = prob + LenHigh;
						TREE_DECODE(probLen, (1 << kLenNumHighBits), len);
						len += kLenNumLowSymbols + kLenNumMidSymbols;
					}
				}
			}
			if (state >= kNumStates)
			{
				uint32_t distance;
				prob = probs + PosSlot +
				((len < kNumLenToPosStates ? len : kNumLenToPosStates - 1) << kNumPosSlotBits);
				TREE_6_DECODE(prob, distance);
				if (distance >= kStartPosModelIndex)
				{
					unsigned posSlot = (unsigned)distance;
					unsigned numDirectBits = (unsigned)(((distance >> 1) - 1));
					distance = (2 | (distance & 1));
					if (posSlot < kEndPosModelIndex)
					{
						distance <<= numDirectBits;
						prob = probs + SpecPos + distance - posSlot - 1;
						{
							uint32_t mask = 1;
							unsigned i = 1;
							do
							{
								GET_BIT2(prob + i, i, ; , distance |= mask);
								mask <<= 1;
							}
							while (--numDirectBits != 0);
						}
					}
					else
					{
						numDirectBits -= kNumAlignBits;
						do {
							NORMALIZE
							range >>= 1;
							{
								uint32_t t;
								code -= range;
								t = (0 - ((uint32_t)code >> 31));
								distance = (distance << 1) + (t + 1);
								code += range & t;
							}
						} while (--numDirectBits != 0);
						prob = probs + Align;
						distance <<= kNumAlignBits;
						{
							unsigned i = 1;
							GET_BIT2(prob + i, i, ; , distance |= 1);
							GET_BIT2(prob + i, i, ; , distance |= 2);
							GET_BIT2(prob + i, i, ; , distance |= 4);
							GET_BIT2(prob + i, i, ; , distance |= 8);
						}
						if (distance == (uint32_t)0xFFFFFFFF)
						{
							len += kMatchSpecLenStart;
							state -= kNumStates;
							break;
						}
					}
				}

				rep3 = rep2;
				rep2 = rep1;
				rep1 = rep0;
				rep0 = distance + 1;
				if (checkDicSize == 0)
				{
					if (distance >= processedPos)
					{
						p->dicPos = dicPos;
						return SZ_ERROR_DATA;
					}
				}
				else if (distance >= checkDicSize)
				{
					p->dicPos = dicPos;
					return SZ_ERROR_DATA;
				}
				state = (state < kNumStates + kNumLitStates) ? kNumLitStates : kNumLitStates + 3;
			}
			len += kMatchMinLen;
			{
				size_t rem;
				unsigned curLen;
				size_t pos;

				if ((rem = limit - dicPos) == 0)
				{
					p->dicPos = dicPos;
					return SZ_ERROR_DATA;
				}
				curLen = ((rem < len) ? (unsigned)rem : len);
				pos = dicPos - rep0 + (dicPos < rep0 ? dicBufSize : 0);
				processedPos += curLen;
				len -= curLen;
				if (curLen <= dicBufSize - pos)
				{
					uint8_t *dest = dic + dicPos;
					ptrdiff_t src = (ptrdiff_t)pos - (ptrdiff_t)dicPos;
					const uint8_t *lim = dest + curLen;
					dicPos += curLen;
					do
						*(dest) = (uint8_t)*(dest + src);
					while (++dest != lim);
				}
				else
				{
					do {
						dic[dicPos++] = dic[pos];
						if (++pos == dicBufSize) pos = 0;
					} while (--curLen != 0);
				}
			}
		}
	}
	while (dicPos < limit && buf < bufLimit);
	NORMALIZE;
	p->buf = buf;
	p->range = range;
	p->code = code;
	p->remainLen = len;
	p->dicPos = dicPos;
	p->processedPos = processedPos;
	p->reps[0] = rep0;
	p->reps[1] = rep1;
	p->reps[2] = rep2;
	p->reps[3] = rep3;
	p->state = state;
	return SZ_OK;
}

static int LzmaDec_DecodeReal2(CLzmaDec *p, size_t limit, const uint8_t *bufLimit) {
	do {
		size_t limit2 = limit;
		if (p->checkDicSize == 0)
		{
			uint32_t rem = p->prop.dicSize - p->processedPos;
			if (limit - p->dicPos > rem)
				limit2 = p->dicPos + rem;
		}
		RINOK(LzmaDec_DecodeReal(p, limit2, bufLimit));
		if (p->checkDicSize == 0 && p->processedPos >= p->prop.dicSize) p->checkDicSize = p->prop.dicSize;
		LzmaDec_WriteRem(p, limit);
	}
	while (p->dicPos < limit && p->buf < bufLimit && p->remainLen < kMatchSpecLenStart);
	if (p->remainLen > kMatchSpecLenStart) p->remainLen = kMatchSpecLenStart;
	return 0;
}

static int LzmaDec_DecodeToDic(CLzmaDec *p, size_t dicLimit, const uint8_t *src, size_t *srcLen,
							   ELzmaFinishMode finishMode, ELzmaStatus *status) {
	size_t inSize = *srcLen;
	(*srcLen) = 0;
	LzmaDec_WriteRem(p, dicLimit);
	*status = LZMA_STATUS_NOT_SPECIFIED;
	while (p->remainLen != kMatchSpecLenStart)
	{
		int checkEndMarkNow;
		if (p->needFlush)
		{
			for (; inSize > 0 && p->tempBufSize < RC_INIT_SIZE; (*srcLen)++, inSize--) p->tempBuf[p->tempBufSize++] = *src++;
			if (p->tempBufSize < RC_INIT_SIZE)
			{
				*status = LZMA_STATUS_NEEDS_MORE_INPUT;
				return SZ_OK;
			}
			if (p->tempBuf[0] != 0) return SZ_ERROR_DATA;
			p->code =
			((uint32_t)p->tempBuf[1] << 24)
			| ((uint32_t)p->tempBuf[2] << 16)
			| ((uint32_t)p->tempBuf[3] << 8)
			| ((uint32_t)p->tempBuf[4]);
			p->range = 0xFFFFFFFF;
			p->needFlush = 0;
			p->tempBufSize = 0;
		}
		checkEndMarkNow = 0;
		if (p->dicPos >= dicLimit)
		{
			if (p->remainLen == 0 && p->code == 0)
			{
				*status = LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK;
				return SZ_OK;
			}
			if (finishMode == LZMA_FINISH_ANY)
			{
				*status = LZMA_STATUS_NOT_FINISHED;
				return SZ_OK;
			}
			if (p->remainLen != 0)
			{
				*status = LZMA_STATUS_NOT_FINISHED;
				return SZ_ERROR_DATA;
			}
			checkEndMarkNow = 1;
		}

		if (p->needInitState) LzmaDec_InitStateReal(p);
		if (p->tempBufSize == 0)
		{
			size_t processed;
			const uint8_t *bufLimit;
			if (inSize < LZMA_REQUIRED_INPUT_MAX || checkEndMarkNow)
			{
				int dummyRes = LzmaDec_TryDummy(p, src, inSize);
				if (dummyRes == DUMMY_ERROR)
				{
					memcpy(p->tempBuf, src, inSize);
					p->tempBufSize = (unsigned)inSize;
					(*srcLen) += inSize;
					*status = LZMA_STATUS_NEEDS_MORE_INPUT;
					return SZ_OK;
				}
				if (checkEndMarkNow && dummyRes != DUMMY_MATCH)
				{
					*status = LZMA_STATUS_NOT_FINISHED;
					return SZ_ERROR_DATA;
				}
				bufLimit = src;
			}
			else bufLimit = src + inSize - LZMA_REQUIRED_INPUT_MAX;
			p->buf = src;
			if (LzmaDec_DecodeReal2(p, dicLimit, bufLimit) != 0) return SZ_ERROR_DATA;
			processed = (size_t)(p->buf - src);
			(*srcLen) += processed;
			src += processed;
			inSize -= processed;
		}
		else
		{
			unsigned rem = p->tempBufSize, lookAhead = 0;
			while (rem < LZMA_REQUIRED_INPUT_MAX && lookAhead < inSize) p->tempBuf[rem++] = src[lookAhead++];
			p->tempBufSize = rem;
			if (rem < LZMA_REQUIRED_INPUT_MAX || checkEndMarkNow)
			{
				int dummyRes = LzmaDec_TryDummy(p, p->tempBuf, rem);
				if (dummyRes == DUMMY_ERROR)
				{
					(*srcLen) += lookAhead;
					*status = LZMA_STATUS_NEEDS_MORE_INPUT;
					return SZ_OK;
				}
				if (checkEndMarkNow && dummyRes != DUMMY_MATCH)
				{
					*status = LZMA_STATUS_NOT_FINISHED;
					return SZ_ERROR_DATA;
				}
			}
			p->buf = p->tempBuf;
			if (LzmaDec_DecodeReal2(p, dicLimit, p->buf) != 0) return SZ_ERROR_DATA;
			{
				unsigned kkk = (unsigned)(p->buf - p->tempBuf);
				if (rem < kkk) return SZ_ERROR_FAIL;
				rem -= kkk;
				if (lookAhead < rem) return SZ_ERROR_FAIL;
				lookAhead -= rem;
			}
			(*srcLen) += lookAhead;
			src += lookAhead;
			inSize -= lookAhead;
			p->tempBufSize = 0;
		}
	}
	if (p->code == 0) *status = LZMA_STATUS_FINISHED_WITH_MARK;
	return (p->code == 0) ? SZ_OK : SZ_ERROR_DATA;
}

static int LzmaDecode(uint8_t *dest, size_t *destLen, const uint8_t *src, size_t *srcLen,
					  const uint8_t *propData, unsigned propSize, ELzmaFinishMode finishMode,
					  ELzmaStatus *status, ISzAlloc *alloc) {
	CLzmaDec p;
	size_t outSize = *destLen, inSize = *srcLen;
	*destLen = *srcLen = 0;
	*status = LZMA_STATUS_NOT_SPECIFIED;
	if (inSize < RC_INIT_SIZE) return SZ_ERROR_INPUT_EOF;
	LzmaDec_Construct(&p);
	RINOK(LzmaDec_AllocateProbs(&p, propData, propSize, alloc));
	p.dic = dest;
	p.dicBufSize = outSize;
	LzmaDec_Init(&p);
	*srcLen = inSize;
	int res = LzmaDec_DecodeToDic(&p, outSize, src, srcLen, finishMode, status);
	*destLen = p.dicPos;
	if (res == SZ_OK && *status == LZMA_STATUS_NEEDS_MORE_INPUT) res = SZ_ERROR_INPUT_EOF;
	LzmaDec_FreeProbs(&p, alloc);
	return res;
}

static int LzmaUncompress(uint8_t *dest, size_t *destLen, const uint8_t *src, size_t *srcLen,
						  const uint8_t *props, size_t propsSize) {
	ISzAlloc g_Alloc = { SzAlloc, SzFree };
	ELzmaStatus status;
	return LzmaDecode(dest, destLen, src, srcLen, props, (unsigned)propsSize, LZMA_FINISH_ANY, &status, &g_Alloc);
}


/**
 @brief Get lzma decompressed data.
 @param lzmaData Lzma compressed data.
 @return Decompressed data or nil on error or data is not lzma compressed.
 */
NS_INLINE NSData * NSDataGetLzmaDecompressData(NSData * lzmaData)
{
	if (!lzmaData) return nil;
#if defined(DEBUG)
	assert([lzmaData isKindOfClass:[NSData class]]);
#endif
	const NSUInteger lzmaDataLen = [lzmaData length];
	if (lzmaDataLen < (sizeof(uint32_t) + LZMA_PROPS_SIZE)) return nil;

	uint8_t * sizePtr = (uint8_t *)[lzmaData bytes];
	uint8_t * props = sizePtr + sizeof(uint32_t);
	uint8_t * inBuff = props + LZMA_PROPS_SIZE;

	uint32_t * int32Ptr = (uint32_t *)sizePtr;
	uint8_t * unCompressedBuffer = (uint8_t *)malloc((*int32Ptr));
	if (!unCompressedBuffer) return nil;

	size_t dstLen = *int32Ptr;
	size_t srcLen = [lzmaData length] - LZMA_PROPS_SIZE - sizeof(uint32_t);
	int res = LzmaUncompress((uint8_t *)unCompressedBuffer,
							 &dstLen,
							 inBuff,
							 &srcLen,
							 props,
							 LZMA_PROPS_SIZE);
	if (res == SZ_OK)
	{
		if ((uint32_t)dstLen == (*int32Ptr))
		{
			NSData * d = [NSData dataWithBytesNoCopy:unCompressedBuffer length:dstLen freeWhenDone:YES];
			if (d) return d;
		}
	}
	free(unCompressedBuffer);
	return nil;
}

