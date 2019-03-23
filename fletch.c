/*
 * Copyright 2014-2018, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * fletch.c -- Compute Fletcher-64 and Fletcher-128 checksums on each file specified on the command line
 *
 * usage: fletch files...
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct _f128 {
	uint64_t hi64;
	uint64_t lo64;
};

/*
 * fletcher64 -- compute a Fletcher64 checksum
 *
 * Gold standard implementation used to compare to the
 * util_checksum() being unit tested.
 */
static struct _f128
*fletcher128(void *addr, size_t len)
{
	uint64_t *p64 = addr;
	uint64_t *p64end = (uint64_t *)((char *)addr + len);
	static struct _f128 f128;
	f128.lo64 = 0;
	f128.hi64 = 0;

	while (p64 < p64end) {
		f128.lo64 += le64toh(*p64);
		p64++;
		f128.hi64 += f128.lo64;
	}
	while(len-- % 4 != 0) {
		uint64_t zero = 0;
		f128.lo64 += le64toh(zero);
		f128.hi64 += f128.lo64;
	}
	return &f128;
}

static uint64_t
fletcher64(void *addr, size_t len)
{
	uint32_t *p32 = addr;
	uint32_t *p32end = (uint32_t *)((char *)addr + len);
	uint32_t lo32 = 0;
	uint32_t hi32 = 0;

	while (p32 < p32end) {
		lo32 += le32toh(*p32);
		p32++;
		hi32 += lo32;
	}
	while(len-- % 4 != 0) {
		uint32_t zero = 0;
		lo32 += le32toh(zero);
		hi32 += lo32;
	}

	return htole64((uint64_t)hi32 << 32 | lo32);
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s files...\n", argv[0]);
		exit(-1);
	}
	printf("%-30s %-12s %-16s %-32s\n", "file", "bytes", "Fletcher-64", "Fletcher-128");

	int arg = 0;
	for (arg = 1; arg < argc; arg++) {
		int fd = open(argv[arg], O_RDONLY);
		if(fd == -1) {
			fprintf(stderr, "Cannot open file: %s\n", argv[arg]);
			exit(-1);
		}

		struct stat stbuf;
		fstat(fd, &stbuf);
		size_t size = (size_t)stbuf.st_size;

		/* pad to 32 bit blocks */
		void *addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
		assert(addr != NULL);

		/* calculate checksum */
		uint64_t csum = fletcher64(addr, size);

		struct _f128 *f128 = fletcher128(addr, size);
		printf("%-30s %-12lu %016lx %016lx%016lx\n", argv[arg], size, csum, f128->hi64, f128->lo64);

		close(fd);
		munmap(addr, size);

	}

	exit(0);
}
