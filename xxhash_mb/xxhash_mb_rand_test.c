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

#include "xxhash_mb.h"
#include "endian_helper.h"

#define MAX_BUF_SIZE	(16 << 20)	// 16MB
#define MIN_BUF_SIZE	1

struct buf_list {
	void		*addr;
	size_t		size;
	struct buf_list	*next;
};

/*
 * Create a buffer list. Each list item contains with random buffer size.
 * The next field of last item is always NULL.
 */
static struct buf_list *alloc_buffer(int nums)
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
		list[i].size = (size_t)(rand() / 100000);
		list[i].size = 256;
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

/* Fill random data into the whole buffer list. */
static void fill_rand_buffer(struct buf_list *list)
{
	struct buf_list *p = list;
	unsigned char *u;
	int i;

	while (p) {
		if (p->addr) {
			u = (unsigned char *)p->addr;
			for (i = 0; i < p->size; i++)
				u[i] = (unsigned char)0xa7;
				//u[i] = (unsigned char)rand();
			for (i = 0; i < p->size; i++) {
				printf("%02x ", u[i]);
				if (i % 16 == 0)
					printf("\n");
			}
			printf("\n");
		}
		p = p->next;
	}
}

static int verify_digest(struct buf_list *list, uint32_t digest)
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
		printf("Digest %x is matched!\n", digest);
		return 0;
	}
	printf("Input digest vs verified digest: %x VS %x\n", digest, h32);
	return -EINVAL;
}

struct ctx_user_data {
	uint32_t	seed;
};

int run_single_ctx(void)
{
	struct buf_list *list;
	XXH32_HASH_CTX_MGR *mgr;
	XXH32_HASH_CTX ctx;
	struct ctx_user_data udata;
	int ret, i, flags;
	int buf_cnt = 1;

	list = alloc_buffer(buf_cnt);
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
printf("#%s, %d, size:0x%lx\n", __func__, __LINE__, list[i].size);
		xxh32_ctx_mgr_submit(mgr, &ctx, list[i].addr, list[i].size,
				     flags);
printf("#%s, %d\n", __func__, __LINE__);
		xxh32_ctx_mgr_flush(mgr);
printf("#%s, %d\n", __func__, __LINE__);
	}
	verify_digest(list, ctx.job.result_digest);
	free_buffer(list);
	return 0;
out:
	free_buffer(list);
	return ret;
}

int main(void)
{
	run_single_ctx();
	return 0;
}
