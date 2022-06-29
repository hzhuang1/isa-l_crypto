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
#include <aarch64_multibinary.h>

#define SVE_CPUID_MASK		(0xFUL << 32)

DEFINE_INTERFACE_DISPATCHER(xxh32_ctx_mgr_init)
{
	uint64_t cpuid;

	__asm__ __volatile__("mrs %0, ID_AA64PFR0_EL1" : "=r"(cpuid));
	if (cpuid & SVE_CPUID_MASK)
		return PROVIDER_INFO(xxh32_ctx_mgr_init_sve);

	return PROVIDER_BASIC(xxh32_ctx_mgr_init);
}

DEFINE_INTERFACE_DISPATCHER(xxh32_ctx_mgr_submit)
{
	uint64_t cpuid;

	__asm__ __volatile__("mrs %0, ID_AA64PFR0_EL1" : "=r"(cpuid));
	if (cpuid & SVE_CPUID_MASK)
		return PROVIDER_INFO(xxh32_ctx_mgr_submit_sve);

	return PROVIDER_BASIC(xxh32_ctx_mgr_submit);
}

DEFINE_INTERFACE_DISPATCHER(xxh32_ctx_mgr_flush)
{
	uint64_t cpuid;

	__asm__ __volatile__("mrs %0, ID_AA64PFR0_EL1" : "=r"(cpuid));
	if (cpuid & SVE_CPUID_MASK)
		return PROVIDER_INFO(xxh32_ctx_mgr_flush_sve);

	return PROVIDER_BASIC(xxh32_ctx_mgr_flush);
}
