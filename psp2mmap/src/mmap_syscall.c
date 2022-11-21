

#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/cpu.h>
#include "mmap_internal.h"
#include "../../mmap_user.h"


int mmap_for_user(void *addr, size_t length, int prot, MmapParam *param){

	int res, state;
	MmapParam k_param;

	ENTER_SYSCALL(state);

	res = ksceKernelMemcpyFromUser(&k_param, param, sizeof(k_param));
	if(res >= 0){
		res = mmap_core(addr, length, prot, &k_param);
		if(res >= 0){
			ksceKernelMemcpyToUser(param, &k_param, sizeof(*param));
		}
	}

	EXIT_SYSCALL(state);

	return res;
}

int munmap(void *addr, size_t length){

	SceUID pid;

	if(addr == NULL || (length & 0xFFF) != 0){
		return 0x80000000;
	}

	pid = ksceKernelGetProcessId();
	if(pid < 0){
		return pid;
	}

	return munmap_core(pid, addr, length);
}
