/**********************************************************************
  Copyright(c) 2022 Linaro Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Linaro Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#include <stdint.h>
#include <string.h>
#include "xxhash_mb.h"

/*-****************************
 * Simple Hash Functions
 *****************************/

/**
 * xxh32() - calculate the 32-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 32-bit hash of the data.
 */
uint32_t xxh32(const void *input, size_t length, uint32_t seed);

/**
 * xxh64() - calculate the 64-bit hash of the input with a given seed.
 *
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 * @seed:   The seed can be used to alter the result predictably.
 *
 * Return:  The 64-bit hash of the data.
 */
uint64_t xxh64(const void *input, size_t length, uint64_t seed);

/*-****************************
 * Streaming Hash Functions
 *****************************/

#if 0
/**
 * struct xxh32_state - private xxh32 state, do not use members directly
 */
struct xxh32_state {
	uint32_t total_len_32;
	uint32_t large_len;
	uint32_t v[4];
	uint32_t mem32[4];
	uint32_t memsize;
	uint32_t reserved;
};

/**
 * struct xxh32_state - private xxh64 state, do not use members directly
 */
struct xxh64_state {
	uint64_t total_len;
	uint64_t v[4];
	uint64_t mem64[4];
	uint32_t memsize;
	uint32_t reserved32;
	uint64_t reserved64;
};
#endif

/**
 * xxh32_reset() - reset the xxh32 state to start a new hashing operation
 *
 * @state: The xxh32 state to reset.
 * @seed:  Initialize the hash state with this seed.
 *
 * Call this function on any xxh32_state to prepare for a new hashing operation.
 */
void xxh32_reset(XXH32_HASH_CTX *ctx, uint32_t seed);

/**
 * xxh32_update() - hash the data given and update the xxh32 state
 *
 * @state:  The xxh32 state to update.
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 *
 * After calling xxh32_reset() call xxh32_update() as many times as necessary.
 *
 * Return:  Zero on success, otherwise an error code.
 */
int xxh32_update(XXH32_HASH_CTX *ctx, const void *input, size_t length);

/**
 * xxh32_digest() - produce the current xxh32 hash
 *
 * @state: Produce the current xxh32 hash of this state.
 *
 * A hash value can be produced at any time. It is still possible to continue
 * inserting input into the hash state after a call to xxh32_digest(), and
 * generate new hashes later on, by calling xxh32_digest() again.
 *
 * Return: The xxh32 hash stored in the state.
 */
void xxh32_digest(const XXH32_HASH_CTX *ctx);

/**
 * xxh64_reset() - reset the xxh64 state to start a new hashing operation
 *
 * @state: The xxh64 state to reset.
 * @seed:  Initialize the hash state with this seed.
 */
void xxh64_reset(XXH64_HASH_CTX *ctx, uint64_t seed);

/**
 * xxh64_update() - hash the data given and update the xxh64 state
 * @state:  The xxh64 state to update.
 * @input:  The data to hash.
 * @length: The length of the data to hash.
 *
 * After calling xxh64_reset() call xxh64_update() as many times as necessary.
 *
 * Return:  Zero on success, otherwise an error code.
 */
int xxh64_update(XXH64_HASH_CTX *ctx, const void *input, size_t length);

/**
 * xxh64_digest() - produce the current xxh64 hash
 *
 * @state: Produce the current xxh64 hash of this state.
 *
 * A hash value can be produced at any time. It is still possible to continue
 * inserting input into the hash state after a call to xxh64_digest(), and
 * generate new hashes later on, by calling xxh64_digest() again.
 *
 * Return: The xxh64 hash stored in the state.
 */
uint64_t xxh64_digest(const XXH64_HASH_CTX *ctx);


/*-**************************
 * Utils
 ***************************/

/*-*************************************
 * Macros
 **************************************/
#define XXH_rotl32(x, r)	(((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_rotl64(x, r)	(((x) << (r)) | ((x) >> (64 - (r))))

/*-*************************************
 * Constants
 **************************************/
static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

/*
static const uint64_t PRIME64_1 = 11400714785074694791ULL;
static const uint64_t PRIME64_2 = 14029467366897019727ULL;
static const uint64_t PRIME64_3 =  1609587929392839161ULL;
static const uint64_t PRIME64_4 =  9650029242287828579ULL;
static const uint64_t PRIME64_5 =  2870177450012600261ULL;
*/

void xxh32_ctx_mgr_init_base(XXH32_HASH_CTX_MGR * mgr)
{
}

XXH32_HASH_CTX *xxh32_ctx_mgr_submit_base(XXH32_HASH_CTX_MGR *mgr,
					  XXH32_HASH_CTX *ctx,
					  const void *buffer,
					  uint32_t len,
					  uint32_t seed,
					  HASH_CTX_FLAG flags)
{
	if (flags & (~HASH_ENTIRE)) {
		// User should not pass anything other than FIRST, UPDATE or
		// LAST.
		ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
		return ctx;
	}

	if ((ctx->status & HASH_CTX_STS_PROCESSING) &&
	    (flags == HASH_ENTIRE)) {
		// Cannot submit a new entire job to a currently processing
		// job.
		ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
		return ctx;
	}

	if ((ctx->status & HASH_CTX_STS_COMPLETE) && !(flags & HASH_FIRST)) {
		// Cannot update a finished job.
		ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
		return ctx;
	}

	switch (flags) {
	case HASH_FIRST:
		xxh32_reset(ctx, seed);
		xxh32_update(ctx, buffer, len);
		break;
	case HASH_UPDATE:
		xxh32_update(ctx, buffer, len);
		break;
	case HASH_LAST:
		xxh32_update(ctx, buffer, len);
		xxh32_digest(ctx);
		break;
	case HASH_ENTIRE:
		xxh32_reset(ctx, seed);
		xxh32_update(ctx, buffer, len);
		xxh32_digest(ctx);
		break;
	}

	return ctx;
}

XXH32_HASH_CTX *xxh32_ctx_mgr_flush_base(XXH32_HASH_CTX_MGR *mgr)
{
	return NULL;
}

void xxh32_reset(XXH32_HASH_CTX *ctx, uint32_t seed)
{
	// Init digest
	ctx->job.result_digest[0] = 0;

	// Reset byte counter
	ctx->total_length = 0;

	// Clear extra blocks
	ctx->partial_block_buffer_length = 0;

	// If we made it here, there were no errors during this call to submit
	ctx->error = HASH_CTX_ERROR_NONE;

	// Mark it as processing
	ctx->status = HASH_CTX_STS_PROCESSING;

	ctx->v[0] = seed + PRIME32_1 + PRIME32_2;
	ctx->v[1] = seed + PRIME32_2;
	ctx->v[2] = seed + 0;
	ctx->v[3] = seed - PRIME32_1;
}

static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = XXH_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

/* assume partial_block_buffer_length < 16!!! Need to fix? */
int xxh32_update(XXH32_HASH_CTX *ctx, const void *input, size_t len)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *const b_end = p + len;

	ctx->total_length += (uint32_t)len;
	ctx->large_len |= (uint32_t)((len >= 16) | (ctx->total_length >= 16));

	if (ctx->partial_block_buffer_length + len < 16) {
		/* fill in the partial block buffer */
		memcpy(ctx->partial_block_buffer +
		       ctx->partial_block_buffer_length,
		       input,
		       len);
		ctx->partial_block_buffer_length += (uint32_t)len;
		return 0;
	}

	if (ctx->partial_block_buffer_length) {
		/* data left from previous update */
		memcpy(ctx->partial_block_buffer +
		       ctx->partial_block_buffer_length,
		       input,
		       16 - ctx->partial_block_buffer_length);
		{
			const uint32_t *p32 =
				(const uint32_t *)ctx->partial_block_buffer;
			ctx->v[0] = xxh32_round(ctx->v[0], *p32);
			p32++;
			ctx->v[1] = xxh32_round(ctx->v[1], *p32);
			p32++;
			ctx->v[2] = xxh32_round(ctx->v[2], *p32);
			p32++;
			ctx->v[3] = xxh32_round(ctx->v[3], *p32);
		}
		p += 16 - ctx->partial_block_buffer_length;
		ctx->partial_block_buffer_length = 0;
	}

	if (p <= b_end - 16) {
		const uint8_t *const limit = b_end - 16;

		do {
			ctx->v[0] = xxh32_round(ctx->v[0], *(uint32_t *)p);
			p += 4;
			ctx->v[1] = xxh32_round(ctx->v[1], *(uint32_t *)p);
			p += 4;
			ctx->v[2] = xxh32_round(ctx->v[2], *(uint32_t *)p);
			p += 4;
			ctx->v[3] = xxh32_round(ctx->v[3], *(uint32_t *)p);
			p += 4;
		} while (p <= limit);
	}

	if (p < b_end) {
		memcpy(ctx->partial_block_buffer, p, (size_t)(b_end - p));
		ctx->partial_block_buffer_length = (uint32_t)(b_end - p);
	}

	return 0;
}

void xxh32_digest(const XXH32_HASH_CTX *ctx)
{
	const uint8_t *p = (const uint8_t *)ctx->partial_block_buffer;
	const uint8_t *const b_end = (const uint8_t *)ctx->partial_block_buffer
				     + ctx->partial_block_buffer_length;
	uint32_t *digest = (uint32_t *)ctx->job.result_digest;

	if (ctx->large_len) {
		*digest = XXH_rotl32(ctx->v[0], 1) +
			  XXH_rotl32(ctx->v[1], 7) +
			  XXH_rotl32(ctx->v[2], 12) +
			  XXH_rotl32(ctx->v[3], 18);
	} else {
		/* seed + PRIME32_5 */
		*digest = ctx->v[2] + PRIME32_5;
	}

	*digest += ctx->total_length;

	while (p + 4 <= b_end) {
		*digest += *(uint32_t *)p * PRIME32_3;
		*digest = XXH_rotl32(*digest, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		*digest += *p * PRIME32_5;
		*digest = XXH_rotl32(*digest, 11) * PRIME32_1;
		p++;
	}

	*digest ^= *digest >> 15;
	*digest *= PRIME32_2;
	*digest ^= *digest >> 13;
	*digest *= PRIME32_3;
	*digest ^= *digest >> 16;
}

#if 0
uint32_t xxh32(const void *input, const size_t len, const uint32_t seed)
{
	const uint8_t *p = (const uint8_t *)input;
	const uint8_t *b_end = p + len;
	uint32_t h32;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v0 = seed + PRIME32_1 + PRIME32_2;
		uint32_t v1 = seed + PRIME32_2;
		uint32_t v2 = seed + 0;
		uint32_t v3 = seed - PRIME32_1;

		do {
			v0 = xxh32_round(v0, to_le32(p));
			p += 4;
			v1 = xxh32_round(v1, to_le32(p));
			p += 4;
			v2 = xxh32_round(v2, to_le32(p));
			p += 4;
			v3 = xxh32_round(v3, to_le32(p));
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v0, 1) + xxh_rotl32(v1, 7) +
		      xxh_rotl32(v2, 12) + xxh_rotl32(v3, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (uint32_t)len;

	/* XXH_PROCESS4 */
	while (p + 4 <= b_end) {
		h32 += to_le32(p) * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	/* XXH_PROCESS1 */
	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	/* XXH32_avalanche() */
	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}
#endif

