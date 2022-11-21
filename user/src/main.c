
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <psp2/io/stat.h>
#include "../../mmap_user.h"

const char    sceUserMainThreadName[]          = "mmap_user";
const int     sceUserMainThreadPriority        = 0x40;
const int     sceUserMainThreadCpuAffinityMask = 1 << 0;
const SceSize sceUserMainThreadStackSize       = 0x4000;

const int sceKernelPreloadModuleInhibit = SCE_KERNEL_PRELOAD_INHIBIT_LIBC
					| SCE_KERNEL_PRELOAD_INHIBIT_LIBDBG
					| SCE_KERNEL_PRELOAD_INHIBIT_APPUTIL
					| SCE_KERNEL_PRELOAD_INHIBIT_LIBSCEFT2
					| SCE_KERNEL_PRELOAD_INHIBIT_LIBPERF;


int sha256_digest(const void *data, int size, void *hash);


__attribute__((noinline, optimize("O2")))
void hex_dump(const void *addr, int len){

	if(addr == NULL)
		return;

	if(len == 0)
		return;

	while(len >= 0x10){
		sceClibPrintf(
			"%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
			((char *)addr)[0x0], ((char *)addr)[0x1], ((char *)addr)[0x2], ((char *)addr)[0x3],
			((char *)addr)[0x4], ((char *)addr)[0x5], ((char *)addr)[0x6], ((char *)addr)[0x7],
			((char *)addr)[0x8], ((char *)addr)[0x9], ((char *)addr)[0xA], ((char *)addr)[0xB],
			((char *)addr)[0xC], ((char *)addr)[0xD], ((char *)addr)[0xE], ((char *)addr)[0xF]
		);
		addr += 0x10;
		len -= 0x10;
	}

	if(len != 0){
		while(len >= 1){
			sceClibPrintf("%02X ", ((char *)addr)[0x0]);
			addr += 1;
			len -= 1;
		}

		sceClibPrintf("\n");
	}
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, SceOff offset){

	int res;
	MmapParam param;

	param.flags = flags;
	param.fd = fd;
	param.offset = offset;
	param.result = NULL;

	res = mmap_for_user(addr, length, prot, &param);
	if(res < 0){
		return ((void *)-1);
	}

	return param.result;
}


void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	SceInt64 access_s, access_e;

	int size = 0x57000;
	size = 0x200000;

	SceUID fd = sceIoOpen("host0:/psp2core-SceKernelProcess.spsp2dmp.tmp", SCE_O_RDONLY | SCE_O_WRONLY, 0606);

	sceClibPrintf("fd 0x%X\n", fd);

	void *res = mmap((void *)0xF4025000, (size + 0xFFF) & ~0xFFF, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0LL);
	if(res == NULL){
		res = mmap((void *)0xA4025000, (size + 0xFFF) & ~0xFFF, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0LL);
	}

	sceClibPrintf("mmap: 0x%X\n", res);

	sceClibMemset(res, 0xFF, size);

	sceClibSnprintf(res, 0x4000, "Test %lld", sceKernelGetSystemTimeWide());

	access_s = sceKernelGetSystemTimeWide();
	*(volatile int *)(res);
	access_e = sceKernelGetSystemTimeWide();
	sceClibPrintf("Access time: %lld\n", (SceUInt64)(access_e - access_s));

	access_s = sceKernelGetSystemTimeWide();
	*(volatile int *)(res);
	access_e = sceKernelGetSystemTimeWide();
	sceClibPrintf("Access time: %lld\n", (SceUInt64)(access_e - access_s));

	char hash[0x20];

	access_s = sceKernelGetSystemTimeWide();
	sha256_digest(res, size, hash);
	access_e = sceKernelGetSystemTimeWide();
	sceClibPrintf("Hashing time: %lld\n", (SceUInt64)(access_e - access_s));

	sceKernelDelayThread(50000);
	munmap(res, size);
	sceKernelDelayThread(50000);
	sceIoClose(fd);

	hex_dump(hash, sizeof(hash));
	sceClibPrintf("\n");

	sceKernelExitProcess(0);
	sceKernelDelayThread(50000);


	*(volatile int *)(0xC0000000) = 0xAA55AA55;
	sceKernelDelayThread(5000);
	sceClibPrintf("value: 0x%X\n", *(volatile int *)(0xC0000000));
	sceKernelExitProcess(0);
	sceKernelDelayThread(500000);

	return SCE_KERNEL_START_SUCCESS;
}
