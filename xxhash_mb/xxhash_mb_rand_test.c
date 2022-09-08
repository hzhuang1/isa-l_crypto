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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#ifndef XXH_INLINE_ALL
#  define XXH_INLINE_ALL
#endif
#include <xxhash.h>

#include "endian_helper.h"
#include "test.h"
#include "xxhash_mb.h"

#define MAX_BUF_SIZE	(16 << 20)	// 16MB
#define MIN_BUF_SIZE	1

#define SEGMENT_MASK		0xFFFFFFFF00000000UL

#define TEST_PERF_LOOPS		1000
#define TEST_PERF_LEN		256

struct buf_list {
	void		*addr;
	size_t		size;
	struct buf_list	*next;
};

typedef enum {
	XXH32_TEST = 0,
	XXH64_TEST,
} XXH_TEST_TYPE;

extern int xxh32_mb_sve_max_lanes(void);

/*
 * Create a buffer list. Each list item contains with random buffer size.
 * The next field of last item is always NULL.
 */
static struct buf_list *alloc_buffer(int nums, size_t size)
{
	struct buf_list *list;
	struct timeval tv;
	int i;

	if (nums < 0)
		return NULL;
	list = malloc(sizeof(struct buf_list) * nums);
	if (!list)
		return NULL;
	gettimeofday(&tv, NULL);
	srand((unsigned int)tv.tv_usec);
	for (i = 0; i < nums; i++) {
		list[i].next = NULL;
		if (size)
			list[i].size = size;
		else
			list[i].size = (size_t)(rand() / 100000);
		if (list[i].size > MAX_BUF_SIZE)
			list[i].size = MAX_BUF_SIZE;
		else if (list[i].size < MIN_BUF_SIZE)
			list[i].size = MIN_BUF_SIZE;
		list[i].addr = malloc(list[i].size);
		if (!list[i].addr)
			goto out;
		if (i > 0)
			list[i - 1].next = &list[i];
	}
	return list;
out:
	for (; i > 1; i--)
		free(list[i - 1].addr);
	free(list);
	return NULL;
}

/* Free the whole buffer list. */
static void free_buffer(struct buf_list *list)
{
	struct buf_list *p = list;

	while (p) {
		if (p->addr)
			free(p->addr);
		p = p->next;
	}
	free(list);
}

void init_buf(uint8_t *buf, uint8_t val, size_t len)
{
	for (int i = 0; i < len; i++) {
		buf[i] = val + ((i / 8) * 0x10) + (i % 8);
	}
}

void dump_buf(unsigned char *buf, size_t len)
{
        int i;

        for (i = 0; i < len; i += 16) {
                printf("[0x%x]: %02x-%02x-%02x-%02x %02x-%02x-%02x-%02x "
                        "%02x-%02x-%02x-%02x %02x-%02x-%02x-%02x\n",
                        i, buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                        buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
                        buf[i + 12], buf[i + 13], buf[i + 14], buf[i + 15]);
        }
}

#define FILL_RAND_BUFFER

/* Fill random data into the whole buffer list. */
static void fill_rand_buffer(struct buf_list *list)
{
	struct buf_list *p = list;
	unsigned char *u;
#ifdef FILL_RAND_BUFFER
	int i;
#endif

	while (p) {
		if (p->addr) {
			u = (unsigned char *)p->addr;
#ifdef FILL_RAND_BUFFER
			for (i = 0; i < p->size; i++)
				u[i] = (unsigned char)rand();
			/*
			for (i = 0; i < p->size; i++) {
				printf("%02x ", u[i]);
				if (i % 16 == 0)
					printf("\n");
			}
			printf("\n");
			*/
#else
			init_buf(u, 0x37 + (uint8_t)(uint64_t)p->addr, p->size);
			//init_buf(u, 0x37, p->size);
			printf("size:0x%lx\n", p->size);
#endif
		}
		p = p->next;
	}
}

#ifdef DEBUG_NO_TAIL_CALC
static int verify_digest32(struct buf_list *list, uint32_t digest) {}
static int verify_digest64(struct buf_list *list, uint64_t digest) {}
#else
static int verify_digest32(struct buf_list *list, uint32_t digest)
{
	XXH32_state_t state;
	XXH32_hash_t h32;
	struct buf_list *p = list;
	int updated = 0;

	XXH32_reset(&state, 0);
	while (p) {
		if (p->addr) {
			updated |= 1;
			XXH32_update(&state, p->addr, p->size);
		}
		p = p->next;
	}
	if (!updated) {
		fprintf(stderr, "Fail to get digest value for verification!\n");
		return -EINVAL;
	}
	h32 = XXH32_digest(&state);
	if (h32 == digest) {
		//printf("Digest %x is matched!\n", digest);
		return 0;
	}
	printf("Input digest vs verified digest: %x VS %x\n", digest, h32);
	return -EINVAL;
}

static int verify_digest64(struct buf_list *list, uint64_t digest)
{
	XXH64_state_t state;
	XXH64_hash_t h64;
	struct buf_list *p = list;
	int updated = 0;

	XXH64_reset(&state, 0);
	while (p) {
		if (p->addr) {
			updated |= 1;
			XXH64_update(&state, p->addr, p->size);
		}
		p = p->next;
	}
	if (!updated) {
		fprintf(stderr, "Fail to get digest value for verification!\n");
		return -EINVAL;
	}
	h64 = XXH64_digest(&state);
	if (h64 == digest) {
		//printf("Digest %x is matched!\n", digest);
		return 0;
	}
	printf("Input digest vs verified digest: %lx VS %lx\n", digest, h64);
	return -EINVAL;
}
#endif

struct ctx_user_data {
	uint32_t	seed;
};

int run_single_ctx32(void)
{
	struct buf_list *list;
	XXH32_HASH_CTX_MGR *mgr;
	XXH32_HASH_CTX ctx;
	int ret, i, flags;
	int buf_cnt = 1;

	list = alloc_buffer(buf_cnt, 0);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		return -ENOMEM;
	}
	fill_rand_buffer(list);

	mgr = aligned_alloc(16, sizeof(XXH32_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out;
	}
	xxh32_ctx_mgr_init(mgr);
	hash_ctx_init(&ctx);
	ctx.seed = 0;
	for (i = 0; i < buf_cnt; i++) {
		if (buf_cnt == 1)
			flags = HASH_ENTIRE;
		else if (i == 0)
			flags = HASH_FIRST;
		else if (i == (buf_cnt - 1))
			flags = HASH_LAST;
		else
			flags = HASH_UPDATE;
		xxh32_ctx_mgr_submit(mgr, &ctx, list[i].addr,
				list[i].size, flags);
		xxh32_ctx_mgr_flush(mgr);
	}
	free(mgr);
	verify_digest32(list, ctx.job.result_digest);
	free_buffer(list);
	return 0;
out:
	free_buffer(list);
	return ret;
}

int run_single_ctx64(void)
{
	struct buf_list *list;
	XXH64_HASH_CTX_MGR *mgr;
	XXH64_HASH_CTX ctx;
	int ret, i, flags;
	int buf_cnt = 1;

	list = alloc_buffer(buf_cnt, 0);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		return -ENOMEM;
	}
	fill_rand_buffer(list);

	mgr = aligned_alloc(16, sizeof(XXH64_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out;
	}
	xxh64_ctx_mgr_init(mgr);
	hash_ctx_init(&ctx);
	ctx.seed = 0;
	for (i = 0; i < buf_cnt; i++) {
		if (buf_cnt == 1)
			flags = HASH_ENTIRE;
		else if (i == 0)
			flags = HASH_FIRST;
		else if (i == (buf_cnt - 1))
			flags = HASH_LAST;
		else
			flags = HASH_UPDATE;
		xxh64_ctx_mgr_submit(mgr, &ctx, list[i].addr,
				list[i].size, flags);
		xxh64_ctx_mgr_flush(mgr);
	}
	free(mgr);
	verify_digest64(list, ctx.job.result_digest);
	free_buffer(list);
	return 0;
out:
	free_buffer(list);
	return ret;
}

int run_multi_ctx32(int job_cnt)
{
	struct buf_list *listpool[16];
	XXH32_HASH_CTX_MGR *mgr;
	XXH32_HASH_CTX ctxpool[16];
	int ret, i, flags;
	int buf_cnt = 1;

	printf("%s:\n", __func__);
	if (job_cnt < 1)
		job_cnt = 1;
	if (job_cnt > 16)
		job_cnt = 16;
	for (i = 0; i < job_cnt; i++) {
		listpool[i] = alloc_buffer(buf_cnt, 0);
		if (!listpool[i]) {
			fprintf(stderr, "Fail to allocate a buffer list!\n");
			ret = -ENOMEM;
			goto out;
		}
		fill_rand_buffer(listpool[i]);
	}

	mgr = aligned_alloc(16, sizeof(XXH32_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out_mgr;
	}
	xxh32_ctx_mgr_init(mgr);
	for (i = 0; i < job_cnt; i++) {
		hash_ctx_init(&ctxpool[i]);
		flags = HASH_ENTIRE;
		xxh32_ctx_mgr_submit(mgr, &ctxpool[i], listpool[i][0].addr,
				listpool[i][0].size, flags);
	}
	//xxh32_ctx_mgr_flush(mgr);
	while (xxh32_ctx_mgr_flush(mgr));
	for (i = 0; i < job_cnt; i++) {
		printf("[%d] digest:0x%x\n", i, ctxpool[i].job.result_digest);
		ret = verify_digest32(listpool[i], ctxpool[i].job.result_digest);
		if (ret < 0)
			fprintf(stderr, "Fail to verify listpool[%d] (%d)\n", i, ret);
	}
	free(mgr);
	for (i = 0; i < job_cnt; i++)
		free_buffer(listpool[i]);
	return 0;
out_mgr:
	i = job_cnt;
out:
	for (; i > 0; i--)
		free_buffer(listpool[i - 1]);
	return ret;
}

int run_multi_ctx64(int job_cnt)
{
	struct buf_list *listpool[16];
	XXH64_HASH_CTX_MGR *mgr;
	XXH64_HASH_CTX ctxpool[16];
	int ret, i, flags;
	int buf_cnt = 1;

	printf("%s:\n", __func__);
	if (job_cnt < 1)
		job_cnt = 1;
	if (job_cnt > 16)
		job_cnt = 16;
	for (i = 0; i < job_cnt; i++) {
		listpool[i] = alloc_buffer(buf_cnt, 0);
		if (!listpool[i]) {
			fprintf(stderr, "Fail to allocate a buffer list!\n");
			ret = -ENOMEM;
			goto out;
		}
		fill_rand_buffer(listpool[i]);
	}

	mgr = aligned_alloc(16, sizeof(XXH64_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out_mgr;
	}
	xxh64_ctx_mgr_init(mgr);
	for (i = 0; i < job_cnt; i++) {
		hash_ctx_init(&ctxpool[i]);
		flags = HASH_ENTIRE;
		xxh64_ctx_mgr_submit(mgr, &ctxpool[i], listpool[i][0].addr,
				listpool[i][0].size, flags);
	}
	//xxh64_ctx_mgr_flush(mgr);
	while (xxh64_ctx_mgr_flush(mgr));
	for (i = 0; i < job_cnt; i++) {
		printf("[%d] digest:0x%lx\n", i, ctxpool[i].job.result_digest);
		ret = verify_digest64(listpool[i], ctxpool[i].job.result_digest);
		if (ret < 0)
			fprintf(stderr, "Fail to verify listpool[%d] (%d)\n", i, ret);
	}
	free(mgr);
	for (i = 0; i < job_cnt; i++)
		free_buffer(listpool[i]);
	return 0;
out_mgr:
	i = job_cnt;
out:
	for (; i > 0; i--)
		free_buffer(listpool[i - 1]);
	return ret;
}

int run_sb_perf32(int job_cnt, int len)
{
	struct buf_list *list = NULL, *p = NULL;
	int ret, i, t, max_lanes;
	int buf_cnt = 1;
	struct perf start, stop;
	XXH32_state_t state;
	int updated = 0;

	if (job_cnt < 1)
		job_cnt = 1;
	max_lanes = xxh32_mb_sve_max_lanes() / 2;
	if (job_cnt > max_lanes)
		job_cnt = max_lanes;
	printf("%s: job_cnt:%d, max_lanes:%d\n", __func__, job_cnt, max_lanes);

	list = alloc_buffer(buf_cnt, len);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		ret = -ENOMEM;
		goto out;
	}
	fill_rand_buffer(list);

	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		for (i = 0; i < job_cnt; i++) {
			p = list;
			updated = 0;
			XXH32_reset(&state, 0);
			while (p) {
				if (p->addr) {
					updated |= 1;
					XXH32_update(&state, p->addr, p->size);
				}
				p = p->next;
			}
			if (!updated) {
				fprintf(stderr, "Fail to get digest value!\n");
				goto out;
			}
			XXH32_digest(&state);
		}
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * i * t);

	free_buffer(list);
	return 0;
out:
	if (list)
		free_buffer(list);
	return ret;
}

int run_sb_perf64(int job_cnt, int len)
{
	struct buf_list *list = NULL, *p = NULL;
	int ret, i, t, max_lanes;
	int buf_cnt = 1;
	struct perf start, stop;
	XXH64_state_t state;
	int updated = 0;

	if (job_cnt < 1)
		job_cnt = 1;
	max_lanes = xxh32_mb_sve_max_lanes() / 2;
	if (job_cnt > max_lanes)
		job_cnt = max_lanes;
	printf("%s: job_cnt:%d, max_lanes:%d\n", __func__, job_cnt, max_lanes);

	list = alloc_buffer(buf_cnt, len);
	if (!list) {
		fprintf(stderr, "Fail to allocate a buffer list!\n");
		ret = -ENOMEM;
		goto out;
	}
	fill_rand_buffer(list);

	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		for (i = 0; i < job_cnt; i++) {
			p = list;
			updated = 0;
			XXH64_reset(&state, 0);
			while (p) {
				if (p->addr) {
					updated |= 1;
					XXH64_update(&state, p->addr, p->size);
				}
				p = p->next;
			}
			if (!updated) {
				fprintf(stderr, "Fail to get digest value!\n");
				goto out;
			}
			XXH64_digest(&state);
		}
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * i * t);

	free_buffer(list);
	return 0;
out:
	if (list)
		free_buffer(list);
	return ret;
}

int run_mb_perf32(int job_cnt, int len)
{
	struct buf_list *listpool[16];
	XXH32_HASH_CTX_MGR *mgr;
	XXH32_HASH_CTX ctxpool[16];
	int ret = 0, i, t, flags, max_lanes;
	int buf_cnt = 1;
	struct perf start, stop;

	if (job_cnt < 1)
		job_cnt = 1;
	max_lanes = xxh32_mb_sve_max_lanes() / 2;
	if (job_cnt > max_lanes)
		job_cnt = max_lanes;
	printf("%s: job_cnt:%d, max_lanes:%d\n", __func__, job_cnt, max_lanes);
	for (i = 0; i < job_cnt; i++) {
		listpool[i] = alloc_buffer(buf_cnt, len);
		if (!listpool[i]) {
			fprintf(stderr, "Fail to allocate a buffer list!\n");
			ret = -ENOMEM;
			goto out;
		}
		fill_rand_buffer(listpool[i]);
	}
	for (i = 1; i < job_cnt; i++) {
		if (((uint64_t)listpool[i - 1]->addr & SEGMENT_MASK) !=
		    ((uint64_t)listpool[i]->addr & SEGMENT_MASK)) {
			printf("All job buffers are NOT in the same 4GB "
				"memory slot. It could impact performance.\n");
			break;
		}
	}

	mgr = aligned_alloc(16, sizeof(XXH32_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out_mgr;
	}
	xxh32_ctx_mgr_init(mgr);
	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		for (i = 0; i < job_cnt; i++) {
			hash_ctx_init(&ctxpool[i]);
			ctxpool[i].seed = 0;
			flags = HASH_ENTIRE;
			xxh32_ctx_mgr_submit(mgr,
					&ctxpool[i],
					listpool[i][0].addr,
					listpool[i][0].size,
					flags);
		}
		while (xxh32_ctx_mgr_flush(mgr));
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * i * t);

	for (i = 0; i < job_cnt; i++) {
		//printf("[%d] digest:0x%x\n", i, ctxpool[i].job.result_digest);
		ret = verify_digest32(listpool[i], ctxpool[i].job.result_digest);
		if (ret < 0) {
			fprintf(stderr, "Fail to verify listpool[%d] (%d)\n", i, ret);
			break;
		}
	}
	free(mgr);
	for (i = 0; i < job_cnt; i++)
		free_buffer(listpool[i]);
	return 0;
out_mgr:
	i = job_cnt;
out:
	for (; i > 0; i--)
		free_buffer(listpool[i - 1]);
	return ret;
}

int run_mb_perf64(int job_cnt, int len)
{
	struct buf_list *listpool[16];
	XXH64_HASH_CTX_MGR *mgr;
	XXH64_HASH_CTX ctxpool[16];
	int ret = 0, i, t, flags, max_lanes;
	int buf_cnt = 1;
	struct perf start, stop;

	if (job_cnt < 1)
		job_cnt = 1;
	max_lanes = xxh32_mb_sve_max_lanes() / 2;
	if (job_cnt > max_lanes)
		job_cnt = max_lanes;
	printf("%s: job_cnt:%d, max_lanes:%d\n", __func__, job_cnt, max_lanes);
	for (i = 0; i < job_cnt; i++) {
		listpool[i] = alloc_buffer(buf_cnt, len);
		if (!listpool[i]) {
			fprintf(stderr, "Fail to allocate a buffer list!\n");
			ret = -ENOMEM;
			goto out;
		}
		fill_rand_buffer(listpool[i]);
	}
	for (i = 1; i < job_cnt; i++) {
		if (((uint64_t)listpool[i - 1]->addr & SEGMENT_MASK) !=
		    ((uint64_t)listpool[i]->addr & SEGMENT_MASK)) {
			printf("All job buffers are NOT in the same 4GB "
				"memory slot. It could impact performance.\n");
			break;
		}
	}

	mgr = aligned_alloc(16, sizeof(XXH64_HASH_CTX_MGR));
	if (!mgr) {
		fprintf(stderr, "Fail to allocate mgr!\n");
		ret = -ENOMEM;
		goto out_mgr;
	}
	xxh64_ctx_mgr_init(mgr);
	perf_start(&start);
	for (t = 0; t < TEST_PERF_LOOPS; t++) {
		for (i = 0; i < job_cnt; i++) {
			hash_ctx_init(&ctxpool[i]);
			ctxpool[i].seed = 0;
			flags = HASH_ENTIRE;
			xxh64_ctx_mgr_submit(mgr,
					&ctxpool[i],
					listpool[i][0].addr,
					listpool[i][0].size,
					flags);
		}
		while (xxh64_ctx_mgr_flush(mgr));
	}
	perf_stop(&stop);
	perf_print(stop, start, (long long)len * i * t);

	for (i = 0; i < job_cnt; i++) {
		//printf("[%d] digest:0x%x\n", i, ctxpool[i].job.result_digest);
		ret = verify_digest64(listpool[i], ctxpool[i].job.result_digest);
		if (ret < 0) {
			fprintf(stderr, "Fail to verify listpool[%d] (%d)\n", i, ret);
			break;
		}
	}
	free(mgr);
	for (i = 0; i < job_cnt; i++)
		free_buffer(listpool[i]);
	return 0;
out_mgr:
	i = job_cnt;
out:
	for (; i > 0; i--)
		free_buffer(listpool[i - 1]);
	return ret;
}

//#define QUICK_TEST

int main(void)
{
	char str[64];
	int i, len, cnt;


#ifdef QUICK_TEST
	cnt = 8;
#else
	cnt = 15;
#endif

	printf("Test for XXH32:\n");
	run_single_ctx32();
	run_multi_ctx32(2);
	for (i = 0, len = TEST_PERF_LEN; i < cnt; i++) {
		if (len >= 1024 * 1024)
			sprintf(str, "%dMB", len >> 20);
		else if (len >= 1024)
			sprintf(str, "%dKB", len >> 10);
		else
			sprintf(str, "%dB", len);
		printf("Test data buffer with %s size:\n", str);
		run_sb_perf32(16, len);
		run_mb_perf32(1, len);
		run_mb_perf32(2, len);
		run_mb_perf32(4, len);
		run_mb_perf32(8, len);
		run_mb_perf32(16, len);
		len <<= 1;
	}
	printf("Test for XXH64:\n");
	run_single_ctx64();
	run_multi_ctx64(2);
	for (i = 0, len = TEST_PERF_LEN; i < cnt; i++) {
		if (len >= 1024 * 1024)
			sprintf(str, "%dMB", len >> 20);
		else if (len >= 1024)
			sprintf(str, "%dKB", len >> 10);
		else
			sprintf(str, "%dB", len);
		printf("Test data buffer with %s size:\n", str);
		run_sb_perf64(16, len);
		run_mb_perf64(1, len);
		run_mb_perf64(2, len);
		run_mb_perf64(4, len);
		run_mb_perf64(8, len);
		len <<= 1;
	}
	return 0;
}
