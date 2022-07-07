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
#include <stdlib.h>
#include "xxhash_mb.h"
#include "memcpy_inline.h"
#include <stdio.h>

#define PRIME32_1		0x9E3779B1U
#define PRIME32_2		0x85EBCA77U
#define PRIME32_3		0xC2B2AE3DU
#define PRIME32_4		0x27D4EB2FU
#define PRIME32_5		0x165667B1U

#define XXH_rotl32(x, r)	(((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_rotl64(x, r)	(((x) << (r)) | ((x) >> (64 - (r))))

extern void xxh32_mb_mgr_init_sve(XXH32_MB_JOB_MGR *state);
extern XXH32_JOB *xxh32_mb_mgr_submit_sve(XXH32_MB_JOB_MGR *state,
					  XXH32_JOB *job);
extern XXH32_JOB *xxh32_mb_mgr_flush_sve(XXH32_MB_JOB_MGR *state);

static XXH32_HASH_CTX *xxh32_ctx_mgr_resubmit(XXH32_HASH_CTX_MGR *mgr,
					      XXH32_HASH_CTX *ctx);

extern void dump_state(XXH32_MB_JOB_MGR *state);

static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = XXH_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

static inline void xxh32_hash_init_digest(XXH32_HASH_CTX *ctx)
{
	ctx->job.digest[0] = ctx->seed + PRIME32_1 + PRIME32_2;
	ctx->job.digest[1] = ctx->seed + PRIME32_2;
	ctx->job.digest[2] = ctx->seed;
	ctx->job.digest[3] = ctx->seed - PRIME32_1;
	//printf("#%s, %d, init digest, seed:%d, v0:0x%x, v1:0x%x, v2:0x%x, v3:0x%x\n", __func__, __LINE__, ctx->seed, ctx->job.digest[0], ctx->job.digest[1], ctx->job.digest[2], ctx->job.digest[3]);
	//printf("#%s, %d, digest address:0x%p\n", __func__, __LINE__, &ctx->job.digest[0]);
}

static inline uint32_t hash_pad(uint8_t padblock[XXH32_BLOCK_SIZE * 2], uint64_t total_len)
{
	return 0;
}

void xxh32_ctx_mgr_init_sve(XXH32_HASH_CTX_MGR *mgr)
{
	xxh32_mb_mgr_init_sve(&mgr->mgr);
}

static void xxh32_ctx_get_hash(XXH32_HASH_CTX *ctx,
				const void *buffer,
				uint32_t len)
{
	const uint8_t *p = (const uint8_t *)buffer;
	const uint8_t *b_end = p + len;
	uint32_t h32;

//printf("#%s, %d, len:%d, result digest:0x%x, partial_block_buffer_length:%d\n", __func__, __LINE__, len, ctx->job.result_digest, ctx->partial_block_buffer_length);
	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;

		do {
			ctx->job.digest[0] = xxh32_round(ctx->job.digest[0],
							*(uint32_t *)p);
			p += 4;
			ctx->job.digest[1] = xxh32_round(ctx->job.digest[1],
							*(uint32_t *)p);
			p += 4;
			ctx->job.digest[2] = xxh32_round(ctx->job.digest[2],
							*(uint32_t *)p);
			p += 4;
			ctx->job.digest[3] = xxh32_round(ctx->job.digest[3],
							*(uint32_t *)p);
			p += 4;
		} while (p <= limit);
		h32 = XXH_rotl32(ctx->job.digest[0], 1) +
			XXH_rotl32(ctx->job.digest[1], 7) +
			XXH_rotl32(ctx->job.digest[2], 12) +
			XXH_rotl32(ctx->job.digest[3], 18);
	} else if ((len % 16 < 16) && (ctx->total_length >= 256)) {
		h32 = XXH_rotl32(ctx->job.digest[0], 1) +
			XXH_rotl32(ctx->job.digest[1], 7) +
			XXH_rotl32(ctx->job.digest[2], 12) +
			XXH_rotl32(ctx->job.digest[3], 18);
	} else
		h32 = ctx->job.result_digest;

	h32 += ctx->total_length;
//printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);

	while (p + 4 <= b_end) {
		h32 += *(uint32_t *)p * PRIME32_3;
//printf("uint32_t p:0x%x, h32:0x%x\n", *(uint32_t *)p, h32);
		h32 = XXH_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = XXH_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;
//printf("#%s, %d, h32:0x%x\n", __func__, __LINE__, h32);
	ctx->job.result_digest = h32;
}

XXH32_HASH_CTX *xxh32_ctx_mgr_submit_sve(XXH32_HASH_CTX_MGR *mgr,
					 XXH32_HASH_CTX *ctx,
					 const void *buffer,
					 uint32_t len,
					 HASH_CTX_FLAG flags)
{
	XXH32_HASH_CTX *result_ctx;

	if (flags & (~HASH_ENTIRE)) {
		ctx->error = HASH_CTX_ERROR_INVALID_FLAGS;
		return ctx;
	}

	if (ctx->status & HASH_CTX_STS_PROCESSING) {
		//printf("#%s, %d\n", __func__, __LINE__);
		// Cannot submit to a currently processing job.
		ctx->error = HASH_CTX_ERROR_ALREADY_PROCESSING;
		return ctx;
	}

	if ((ctx->status & HASH_CTX_STS_COMPLETE) && !(flags & HASH_FIRST)) {
		//printf("#%s, %d\n", __func__, __LINE__);
		// Cannot update a finished job.
		ctx->error = HASH_CTX_ERROR_ALREADY_COMPLETED;
		return ctx;
	}

	if (flags & HASH_FIRST) {
		// Init digest
		xxh32_hash_init_digest(ctx);

		// Reset byte counter
		ctx->total_length = 0;

		// Clear extra blocks
		ctx->partial_block_buffer_length = 0;
	}
	// If we made it here, there were no errors during this call to submit
	ctx->error = HASH_CTX_ERROR_NONE;

	// Store buffer ptr info from user
	ctx->incoming_buffer = buffer;
	ctx->incoming_buffer_length = len;

	// Store the user's request flags and mark this ctx as currently being
	// processed.
	ctx->status = (flags & HASH_LAST) ?
		(HASH_CTX_STS) (HASH_CTX_STS_PROCESSING | HASH_CTX_STS_LAST) :
		HASH_CTX_STS_PROCESSING;
//printf("#%s, %d, %s, status:0x%x\n", __func__, __LINE__, (flags & HASH_LAST) ? "last block" : "one of block", ctx->status);

	// Advance byte counter
	ctx->total_length += len;

	// If there is anything currently buffered in the extra blocks, append
	// to it until it contains a whole block.
	// Or if the user's buffer contains less than a whole block, append as
	// much as possible to the extra block.
	if ((ctx->partial_block_buffer_length) | (len < XXH32_BLOCK_SIZE)) {
		// Compute how many bytes to copy from user buffer into extra
		// block
		uint32_t copy_len;

		copy_len = XXH32_BLOCK_SIZE - ctx->partial_block_buffer_length;
		if (len < copy_len)
			copy_len = len;

		if (copy_len) {
			// Copy and update relevant pointers and counters
			memcpy_varlen(&ctx->partial_block_buffer
					[ctx->partial_block_buffer_length],
					buffer,
					copy_len);

			ctx->partial_block_buffer_length += copy_len;
			ctx->incoming_buffer = buffer + copy_len;
			ctx->incoming_buffer_length = len - copy_len;
		}
		// The extra block should never contain more than 1 block here
		assert(ctx->partial_block_buffer_length <= XXH32_BLOCK_SIZE);
		// If the extra block buffer contains exactly 1 block, it can
		// be hashed.
		if (ctx->partial_block_buffer_length >= XXH32_BLOCK_SIZE) {
			ctx->partial_block_buffer_length = 0;

			ctx->job.buffer = ctx->partial_block_buffer;
			ctx->job.blk_len = 1;
			ctx = (XXH32_HASH_CTX *)xxh32_mb_mgr_submit_sve(
					&mgr->mgr,
					&ctx->job);
		}
	}
	//printf("#%s, %d, len:0x%lx, incoming length:0x%lx, status:0x%x, prepare to enter ctx_mgr_resubmit\n", __func__, __LINE__, len, ctx->incoming_buffer_length, ctx->status);

	return xxh32_ctx_mgr_resubmit(mgr, ctx);
}

XXH32_HASH_CTX *xxh32_ctx_mgr_flush_sve(XXH32_HASH_CTX_MGR * mgr)
{
        XXH32_HASH_CTX *ctx;

        while (1) {
                ctx = (XXH32_HASH_CTX *) xxh32_mb_mgr_flush_sve(&mgr->mgr);

                // If flush returned 0, there are no more jobs in flight.
                if (!ctx)
                        return NULL;

		//printf("#%s, %d, prepare to enter ctx_mgr_resubmit\n", __func__, __LINE__);
                // If flush returned a job, verify that it is safe to return to the user.
                // If it is not ready, resubmit the job to finish processing.
                ctx = xxh32_ctx_mgr_resubmit(mgr, ctx);

                // If xxh32_ctx_mgr_resubmit returned a job, it is ready to be returned.
                if (ctx)
                        return ctx;

                // Otherwise, all jobs currently being managed by the HASH_CTX_MGR still need processing. Loop.
        }
}

static XXH32_HASH_CTX *xxh32_ctx_mgr_resubmit(XXH32_HASH_CTX_MGR *mgr,
					      XXH32_HASH_CTX *ctx)
{
	while (ctx) {
		if (ctx->status & HASH_CTX_STS_COMPLETE) {
			// Clear PROCESSING bit
			ctx->status = HASH_CTX_STS_COMPLETE;
			return ctx;
		}
		// If the extra blocks are empty, begin hashing what remains
		// in the user's buffer.
		if (ctx->partial_block_buffer_length == 0 &&
		    ctx->incoming_buffer_length) {
			const void *buffer = ctx->incoming_buffer;
			uint32_t len = ctx->incoming_buffer_length;

			// Only entire blocks can be hashed. Copy remainder to
			// extra blocks buffer.
			uint32_t copy_len = len & (XXH32_BLOCK_SIZE - 1);

			if (copy_len) {
				len -= copy_len;
				memcpy_varlen(ctx->partial_block_buffer,
					      ((const char *)buffer + len),
					      copy_len);
				ctx->partial_block_buffer_length = copy_len;
			}

			ctx->incoming_buffer_length = 0;

			// len should be a multiple of the block size now
			assert((len % XXH32_BLOCK_SIZE) == 0);

			if (len) {
				ctx->job.buffer = (uint8_t *) buffer;
				ctx->job.blk_len = len >> XXH32_LOG2_BLOCK_SIZE;
			//printf("#%s, %d, submit job buffer:0x%p, len:0x%x\n", __func__, __LINE__, ctx->job.buffer, ctx->job.blk_len);
				ctx = (XXH32_HASH_CTX *)xxh32_mb_mgr_submit_sve(
						&mgr->mgr,
						&ctx->job);
				continue;
			}
		}
		// If the extra blocks are not empty, then we are either on the
		// last block(s) or we need more user input before continuing.
		if (ctx->status & HASH_CTX_STS_LAST) {

			uint8_t *buf = ctx->partial_block_buffer;
			//uint32_t n_extra_blocks = hash_pad(buf, ctx->total_length);

			ctx->status = HASH_CTX_STS_PROCESSING |
				      HASH_CTX_STS_COMPLETE;
			//printf("#%s, %d, status:0x%x\n", __func__, __LINE__, ctx->status);

			ctx->job.buffer = buf;
			//ctx->job.len = n_extra_blocks;
			//printf("#%s, %d, len:0x%lx, total_length:%d\n", __func__, __LINE__, ctx->job.blk_len, ctx->total_length);
			if (ctx->total_length < 16) {
				// Don't use ctx->job.digest[].
				ctx->job.result_digest = ctx->seed + PRIME32_5;
				xxh32_ctx_get_hash(ctx, buf,
					ctx->partial_block_buffer_length);
			} else {
				//printf("#%s, %d\n", __func__, __LINE__);
				if (ctx->total_length < XXH32_BLOCK_SIZE)
					xxh32_ctx_get_hash(ctx, buf,
						ctx->partial_block_buffer_length);
				else {
					//printf("#%s, %d\n", __func__, __LINE__);
					ctx = (XXH32_HASH_CTX *)xxh32_mb_mgr_submit_sve(
								&mgr->mgr,
								&ctx->job);
			//printf("#%s, %d, status:0x%x\n", __func__, __LINE__, ctx->status);
					xxh32_ctx_get_hash(ctx, buf, ctx->partial_block_buffer_length);
				}
			}
			continue;
		}

		if (ctx)
			ctx->status = HASH_CTX_STS_IDLE;
		return ctx;
	}

	return NULL;
}
