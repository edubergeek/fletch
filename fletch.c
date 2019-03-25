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
 * GPU accelerated version
 * 
 * pattern:
 * Get # of SMs in GPU
 * malloc and device alloc
 * allocate 128 32 bit integers in host memory
 * alloc and intialize to zero 128 32 bit integers in device memory
 * do until EOF
 *   read 64 4k contiguous blocks from file (how to handle the last chunk)
 *   sync threads
 *   copy host to device 
 *   launch 64 threads that each compute Fletcher-64 on 64x 64 bit (8 byte) 4K blocks
 *     512 steps updating each thread's hi and lo register
 * copy 128 32 bit integers from device to host memory
 * pad the last 64 64 bit blocks with zeros in CPU memory
 * output 64x 16 byte checksums
 *
 * usage: fletch files...
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#undef _DEBUG

#define DISK_BLKSZ 4096
#define STRIPES 1

struct _f128 { uint64_t hi64;
	uint64_t lo64;
};

static struct _f128 *f128;
static char *disk_block;
static size_t block_size = DISK_BLKSZ;
static int stripes = STRIPES;

/*
 * fletcher128 -- compute a Fletcher128 checksum
 *
 */
void fletcher128_striped(struct _f128 *f128, char *addr, size_t len)
{
	/* NOTE len is a byte count not a block or uint64_t count */
	uint64_t zeropad = 0;
	int b;
	int full_stripes = stripes;
	int zero_stripes = 0;
	uint64_t zero_len = 0;

	if(len < stripes*block_size) {
		full_stripes = len / block_size;
		if(len % block_size) {
			zero_stripes = 1;
			zero_len = (uint64_t)len % block_size;
			/* handle lengths that don't fall on a 64 bit aligned address */
			zeropad = zero_len % 8;
			if(zeropad) {
				/* invert from length of data in incomplete block to number of pad positions */
 				zeropad = 8 - zeropad;
				/* now coerce the length so as to end on the next uint64_t aligned pointer */
				zero_len += zeropad;
				/* finally, pad with zeros to the next uint64_t aligned pointer */
				memset(addr+(full_stripes*block_size)+zero_len-zeropad,0,zeropad);
			}
#ifdef _DEBUG
			printf("full %d zero %d len %lu zero_len %lu zeropad %lu\n", full_stripes, zero_stripes, len, zero_len, zeropad);
#endif
		}
	}
	else
		len /= stripes;
	/* each stripe is accumulated into pf128[stripe] */
	/* set up an array of block pointers one for each stripe */
	uint64_t *p64 = (uint64_t*)(addr);
	uint64_t *p64end = (uint64_t *)(addr + full_stripes*block_size);
	size_t bytes = 0;
	if(zero_stripes)
		p64end = (uint64_t *)(addr + (full_stripes*block_size) + zero_len);
	while (p64 < p64end) {
		for(b=0;b<stripes;b++) {
			if (p64 < p64end) {
				f128[b].lo64 += le64toh(*p64);
				p64++;
				f128[b].hi64 += f128[b].lo64;
				bytes += sizeof(*p64);
			}
		}
#ifdef _DEBUG
		if(bytes % 4096 == 0) {
			int s = 0;
 			printf("%016lx ", bytes);
			while(s < stripes) {
 				printf("%016lx%016lx", f128[s].hi64, f128[s].lo64);
				s++;
			}
 			printf("\n");
		}
#endif

	}
	return;
}

static struct _f128 *
fletcher128(void *addr, size_t len)
{
	uint64_t zeropad = len % 8;
	uint64_t *p64 = addr;
	uint64_t *p64end = (uint64_t *)((char *)addr + len - zeropad);
	static struct _f128 f128;
	f128.lo64 = 0;
	f128.hi64 = 0;
	uint64_t bytes = 0;

	while (p64 < p64end) {
		f128.lo64 += le64toh(*p64);
		p64++;
		bytes -= sizeof(*p64);
		f128.hi64 += f128.lo64;
#ifdef _DEBUG
		if(bytes % block_size == 0)
			printf("%016lx%016lx\n", f128.hi64, f128.lo64);
#endif

	}
	if(zeropad) {
		/* printf("fletcher128: custom craft final block\n"); */
		union { 
			char pc[8];
			uint64_t pll;
		} pad;
		int p = 0;
		while(zeropad > 0)
			pad.pc[p++] = ((char*)addr)[len-(zeropad--)];
		while(p < 8)
			pad.pc[p++] = 0;
		f128.lo64 += le64toh(pad.pll);
		f128.hi64 += f128.lo64;
	}
#ifdef _DEBUG
	printf("%016lx%016lx\n", f128.hi64, f128.lo64);
#endif

	return &f128;
}

static uint64_t
fletcher64(void *addr, size_t len)
{
	uint64_t zeropad = len % 4;
	uint32_t *p32 = addr;
	uint32_t *p32end = (uint32_t *)((char *)addr + len - zeropad);
	uint32_t lo32 = 0;
	uint32_t hi32 = 0;

	while (p32 < p32end) {
		lo32 += le32toh(*p32);
		p32++;
		hi32 += lo32;
	}
	if(zeropad) {
		/* printf("fletcher64: custom craft final block\n"); */
		union { 
			char pc[4];
			uint32_t pl;
		} pad;
		int p = 0;
		while(zeropad--)
			pad.pc[p++] = ((char*)addr)[len++];
		while(p < 4)
			pad.pc[p++] = 0;
		lo32 += le32toh(pad.pl);
		hi32 += lo32;
	}

	return htole64((uint64_t)hi32 << 32 | lo32);
}

int
main(int argc, char *argv[])
{
	char* progname;
	(progname = strrchr(argv[0], '/')) ? ++progname : (progname = argv[0]);
	if (argc < 2) {
		fprintf(stderr, "usage: %s files...\n", progname);
		exit(-1);
	}

	/*
	 * TODO add command line options -s stripes and -h (help)
	 */
	int arg;
	int c;

	opterr = 0;

	while ((c = getopt (argc, argv, "b:s:")) != -1) {
		switch (c)
		{
		case 'b':
			block_size = (size_t)strtol(optarg, NULL, 0);
			block_size = (block_size / 8) * 8;
			break;
		case 's':
			stripes = atoi(optarg);
			break;
		case '?':
			if (optopt == 'b' || optopt == 's')
				fprintf (stderr, "%s: option -%c requires an argument.\n", progname, optopt);
			else if (isprint (optopt))
				fprintf (stderr, "%s: unknown option `-%c'.\n", progname, optopt);
			else
				fprintf (stderr, "%s: unknown option character `\\x%x'.\n", progname, optopt);
			return 1;
		default:
			abort ();
		}

	}

	/* allocate disk buffer for stripes x blocks */
	disk_block = calloc(block_size, stripes);
	assert(disk_block != NULL);
	/* allocate disk buffer for stripes x checksums */
	f128 = calloc(sizeof(struct _f128), stripes);
	assert(f128 != NULL);

	for (arg = optind; arg < argc; arg++) {
		int fd = open(argv[arg], O_RDONLY);
		if(fd == -1) {
			fprintf(stderr, "%s: cannot open file: %s\n", progname, argv[arg]);
			exit(-1);
		}

		struct stat stbuf;
		fstat(fd, &stbuf);
		size_t size = (size_t)stbuf.st_size;

		if(!strcmp(progname,"fletcher64")) {
			/* pad to 32 bit blocks */
			void *addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
			assert(addr != NULL);

			/* calculate fletch-64 checksum */
			uint64_t csum = fletcher64(addr, size);
			printf("%016lx%016lx %s\n", csum, size, argv[arg]);
			munmap(addr, size);
		}

		else if(!strcmp(progname,"fletcher128")) {
			/* pad to 64 bit blocks */
			void *addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
			assert(addr != NULL);

			/* calculate fletcher-128 */
			struct _f128*  f128sum = fletcher128(addr, size);
			printf("%016lx%016lx%016lx %s\n", f128sum->hi64, f128sum->lo64, size, argv[arg]);
			munmap(addr, size);
		}
		else {
			memset(f128,0, stripes * sizeof(*f128));
			/* calculate strided Fletch-128 checksum */
			size_t remain = size;
			while(remain > 0) {
				/* read the file stripes blocks of size block_size per iteration */
				size_t len;
				len  = read(fd, disk_block, stripes*block_size);
				if(len) {
					fletcher128_striped(f128, disk_block, len);
				}
				remain -= len;
			}
			int s = 0;
			while(s < stripes) {
 				printf("%016lx%016lx", f128[s].hi64, f128[s].lo64);
				s++;
			}
			printf("%016lx %s\n", size, argv[arg]);
		}

		close(fd);

	}
	free(disk_block);
	free(f128);

	exit(0);
}


