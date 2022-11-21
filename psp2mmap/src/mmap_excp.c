
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include "mmap_internal.h"
#include "sce_as.h"
#include "sysmem_internal.h"


extern SceUID mmap_heapid;

extern int (* PartitionAllocMemBlockInListByAddrByCommandRaw)(SceUIDPartitionObject *pPart, SceKernelAllocMemBlockCommand *cmd, SceIntPtr vbase);
extern int (* TinyPartitionFreeMemBlock)(SceUIDPartitionObject *pPart, SceKernelBlock *pBlockTarget, int flags, void *cb);
extern int (* TinyPartitionFreeMemBlockCallback)(SceUIDPartitionObject *pPart, void *pBlockTarget);



int mmap_excp_read_data(SceUID fd, void *userbase, SceSize length, SceOff offset){

	int res;
	void *kernel_page = NULL;
	SceSize kernel_size = 0;
	SceUInt32 kernel_offset = 0;

	SceUID usermap = ksceKernelUserMap("MmapUserIO", 2, userbase, length, &kernel_page, &kernel_size, &kernel_offset);
	if(usermap < 0){
		return usermap;
	}

	do {
		res = ksceIoPread(fd, kernel_page + kernel_offset, length, offset);
		if(res < 0){
			ksceDebugPrintf("%s: sceIoPread 0x%X\n", __FUNCTION__,  res);
			break;
		}

		res = 0;
	} while(0);

	ksceKernelMemBlockRelease(usermap);

	return res;
}

int mmap_alloc_userpage(SceUID pid, SceUInt32 memtype, SceUIntPtr vbase, SceSize vsize){

	char name[0x20];
	SceKernelAllocMemBlockKernelOpt opt;

	snprintf(name, sizeof(name), "mmap_0x%X", vbase);

	memset(&opt, 0, sizeof(opt));
	opt.size    = sizeof(opt);
	opt.attr    = 1 | SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_HAS_PID;
	opt.field_C = vbase;
	opt.pid     = pid;

	SceUID memid = ksceKernelAllocMemBlock(name, memtype, vsize, &opt);
	if(memid < 0){
		ksceDebugPrintf("%s: sceKernelAllocMemBlock 0x%X with type 0x%X\n", __FUNCTION__, memid, memtype);
		return memid;
	}

	ksceKernelMapBlockUserVisible(memid);

	return memid;
}

int mmap_tiny_alloc(void *pPart, SceUIntPtr vbase, SceSize vsize, SceKernelBlock **ppBlock){

	int res;
	SceKernelAllocMemBlockCommand cmd;
	SceKernelBlock *pBlock;

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = vsize;

	res = PartitionAllocMemBlockInListByAddrByCommandRaw(pPart, &cmd, vbase);
	if(res < 0){
		return res;
	}

	pBlock = cmd.pBlock;
	pBlock->memtype = MMAP_DUMMY_MEMTYPE;
	*ppBlock = pBlock;

	return 0;
}

int mmap_excp_handler(SceUIntPtr DFAR){

	int res;
	SceUID pid;
	MmapProcess *mp;
	MmapContext *mmap_ctx;

	pid = ksceKernelGetProcessId();
	if(pid < 0){
		return 0;
	}

	mp = mmap_get_process(pid);
	if(mp == NULL){
		return 0;
	}

	int intr_prev = ksceKernelCpuSuspendIntr(&(mp->lock));

	mmap_ctx = mmap_search_cb(mp, DFAR);
	if(mmap_ctx == NULL){
		ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
		return 0;
	}

	if(mmap_ctx->prot == PROT_NONE){
		ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
		return 0;
	}

	int core = ksceKernelCpuGetCpuId();

	if(mmap_ctx->core_mapping[core].DFAR == DFAR){
		ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
		return 0;
	}

	MmapCoreMapping *core_mapping = &(mmap_ctx->core_mapping[core]);

	core_mapping->DFAR = DFAR;

	for(int i=0;i<4;i++){
		for(int k=0;k<2;k++){
			MmapBlock *pMmapBlock = mmap_ctx->core_mapping[i].pMmapBlock[k];
			if(pMmapBlock != NULL && (DFAR - pMmapBlock->vbase) < pMmapBlock->vsize){
				ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
				return 1; // Other cores have mapped the target va before reaching this exception
			}
		}
	}


	MmapBlock *pMmapBlock, *mb, *next, *prev;

	SceUIntPtr map_base;
	SceSize map_size, lower_size, upper_size;

	int index = core_mapping->index;

	if(core_mapping->pMmapBlock[index] != NULL){ // commit previous memory contents to file
		pMmapBlock = core_mapping->pMmapBlock[index];
		// ksceDebugPrintf("%s: Already there mapped memblock on index %d. %p 0x%X\n", __FUNCTION__, index, pMmapBlock->vbase, pMmapBlock->vsize);

		// ksceKernelCpuDcacheAndL2WritebackRange((void *)pMmapBlock->vbase, pMmapBlock->vsize);
		asm volatile ("dmb sy\n":::"memory");
		asm volatile ("dsb sy\n":::"memory");
		asm volatile ("isb sy\n":::"memory");
		// ksceKernelCpuDcacheAndL2InvalidateRange((void *)pMmapBlock->vbase, pMmapBlock->vsize);
		asm volatile ("dmb sy\n":::"memory");
		asm volatile ("dsb sy\n":::"memory");
		asm volatile ("isb sy\n":::"memory");

		if((mmap_ctx->prot & PROT_WRITE) != 0 && pMmapBlock->has_data != 0){

			pMmapBlock->has_data = 0;

			void *kernel_page = NULL;
			SceSize kernel_size = 0;
			SceUInt32 kernel_offset = 0;

			SceUID usermap = ksceKernelUserMap("MmapUserIO", 1, (void *)pMmapBlock->vbase, pMmapBlock->vsize, &kernel_page, &kernel_size, &kernel_offset);

			ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
			ksceIoPwrite(mmap_ctx->fd, kernel_page + kernel_offset, pMmapBlock->vsize, mmap_ctx->offset + (((void *)pMmapBlock->vbase) - mmap_ctx->addr));
			intr_prev = ksceKernelCpuSuspendIntr(&(mp->lock));

			ksceKernelMemBlockRelease(usermap);
		}

		ksceKernelFreeMemBlock(pMmapBlock->memid);
		pMmapBlock->memid = -1;

		next = pMmapBlock->next;
		prev = pMmapBlock->prev;

		if(prev != NULL && prev->pBlock != NULL){
			prev->next = next;
			if(next != NULL){
				next->prev = prev;
			}

			TinyPartitionFreeMemBlock(mmap_ctx->pPart, prev->pBlock, 0, TinyPartitionFreeMemBlockCallback);
			prev->pBlock = NULL;

			prev->vsize += pMmapBlock->vsize;

			ksceKernelFreeHeapMemory(mmap_heapid, pMmapBlock);
			pMmapBlock = prev;
		}

		if(next != NULL && next->pBlock != NULL){
			pMmapBlock->next = next->next;
			if(next->next != NULL){
				next->next->prev = pMmapBlock;
			}

			TinyPartitionFreeMemBlock(mmap_ctx->pPart, next->pBlock, 0, TinyPartitionFreeMemBlockCallback);
			next->pBlock = NULL;

			pMmapBlock->vsize += next->vsize;

			ksceKernelFreeHeapMemory(mmap_heapid, next);
		}

		res = mmap_tiny_alloc(mmap_ctx->pPart, pMmapBlock->vbase, pMmapBlock->vsize, &(pMmapBlock->pBlock));
		if(res < 0){
			ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
			return 0;
		}
	}

	// find DABT point
	pMmapBlock = mmap_ctx->pMmapBlock;
	while(pMmapBlock != NULL){
		if((DFAR - pMmapBlock->vbase) < pMmapBlock->vsize){
			break;
		}
		pMmapBlock = pMmapBlock->next;
	}

	if(pMmapBlock == NULL){ // cannot find DABT point
		ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
		return 0;
	}

	map_base = DFAR & ~(MMAP_PAGE_SIZE - 1);

	if(map_base < pMmapBlock->vbase){
		map_base = pMmapBlock->vbase;
	}

	map_size = ((map_base + MMAP_PAGE_SIZE) & ~(MMAP_PAGE_SIZE - 1)) - map_base;

	if((map_base + map_size) >= (pMmapBlock->vbase + pMmapBlock->vsize)){
		map_size = (pMmapBlock->vbase + pMmapBlock->vsize) - map_base;
	}

	// ksceDebugPrintf("DFAR=%p map_base=%p map_size=0x%X\n", DFAR, map_base, map_size);

	lower_size = map_base - pMmapBlock->vbase;
	upper_size = (pMmapBlock->vbase + pMmapBlock->vsize) - (map_base + map_size);

	TinyPartitionFreeMemBlock(mmap_ctx->pPart, pMmapBlock->pBlock, 0, TinyPartitionFreeMemBlockCallback);

	next = pMmapBlock->next;
	prev = pMmapBlock->prev;

	pMmapBlock->pBlock = NULL;
	pMmapBlock->vbase = map_base;
	pMmapBlock->vsize = map_size;
	pMmapBlock->memid = -1;

	if(upper_size != 0){ // split free block
		mb = ksceKernelAllocHeapMemory(mmap_heapid, sizeof(*mb));
		mb->next = pMmapBlock->next;
		mb->prev = pMmapBlock;
		mb->pBlock = NULL;
		mb->vbase = map_base + map_size;
		mb->vsize = upper_size;
		mb->memid = -1;

		pMmapBlock->next = mb;

		res = mmap_tiny_alloc(mmap_ctx->pPart, mb->vbase, mb->vsize, &(mb->pBlock));
		if(res < 0){
			ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
			return 0;
		}
	}

	if(lower_size != 0){ // split free block
		mb = ksceKernelAllocHeapMemory(mmap_heapid, sizeof(*mb));
		mb->next = pMmapBlock;
		mb->prev = pMmapBlock->prev;
		mb->pBlock = NULL;
		mb->vbase = map_base - lower_size;
		mb->vsize = lower_size;
		mb->memid = -1;

		pMmapBlock->prev = mb;
		if(mb->prev != NULL){
			mb->prev->next = mb;
		}else{
			mmap_ctx->pMmapBlock = mb;
		}

		res = mmap_tiny_alloc(mmap_ctx->pPart, mb->vbase, mb->vsize, &(mb->pBlock));
		if(res < 0){
			ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
			return 0;
		}
	}

	res = mmap_alloc_userpage(pid, mmap_ctx->memtype, map_base, map_size);
	if(res < 0){
		ksceDebugPrintf("unlucky! Other core does allocate memblock in %p 0x%X\n", map_base, map_size);
		ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);
		return 0;
	}

	pMmapBlock->memid = res;
	core_mapping->pMmapBlock[index] = pMmapBlock;


	SceOff offset = mmap_ctx->offset + (((void *)map_base) - mmap_ctx->addr);
	SceUID fd = mmap_ctx->fd;

	core_mapping->index = index ^ 1;

	// ksceKernelCpuDcacheAndL2InvalidateRange((void *)pMmapBlock->vbase, pMmapBlock->vsize);
	asm volatile ("dmb sy\n":::"memory");
	asm volatile ("dsb sy\n":::"memory");
	asm volatile ("isb sy\n":::"memory");

	ksceKernelCpuResumeIntr(&(mp->lock), intr_prev);

	res = mmap_excp_read_data(fd, (void *)pMmapBlock->vbase, pMmapBlock->vsize, offset);
	if(res < 0){
		return 0;
	}

	pMmapBlock->has_data = 1;

	return 1;
}

int excp_handler_cfunc(SceUIntPtr DFAR){

	int res, state;

	ENTER_SYSCALL(state);

	res = mmap_excp_handler(DFAR);

	EXIT_SYSCALL(state);

	return res;
}
