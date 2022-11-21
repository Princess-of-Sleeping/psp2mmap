
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/excpmgr.h>
#include <psp2kern/kernel/proc_event.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/io/stat.h>
#include <taihen.h>
#include "mmap_internal.h"
#include "sce_as.h"
#include "sysmem_internal.h"
#include "../../mmap_user.h"


int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr);
int module_get_export_func(SceUID pid, const char *modname, SceNID libnid, SceNID funcnid, uintptr_t *func);


int (* sceKernelSysrootPIDtoAddressSpaceCB)(SceUID pid, SceUIDAddressSpaceObject **ppInfo);

int (* PartitionAllocMemBlockInListByAddrByCommandRaw)(SceUIDPartitionObject *pPart, SceKernelAllocMemBlockCommand *cmd, SceIntPtr vbase);
int (* TinyPartitionAllocMemBlockRaw)(SceUIDPartitionObject *pPart, SceKernelAllocMemBlockCommand *cmd, int size, SceKernelBlock **ppBlock);
int (* TinyPartitionFreeMemBlock)(SceUIDPartitionObject *pPart, SceKernelBlock *pBlockTarget, int flags, void *cb);
int (* TinyPartitionFreeMemBlockCallback)(SceUIDPartitionObject *pPart, void *pBlockTarget);


int prog_start(void){

	int res;
	SceUID module_id;

	module_id = ksceKernelSearchModuleByName("SceSysmem");
	if(module_id < 0){
		return module_id;
	}

	res = module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, module_id, 0, 0xEA84 | 1, (uintptr_t *)&TinyPartitionFreeMemBlockCallback);
	if(res < 0){
		return res;
	}

	res = module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, module_id, 0, 0xF0A8 | 1, (uintptr_t *)&PartitionAllocMemBlockInListByAddrByCommandRaw);
	if(res < 0){
		return res;
	}

	res = module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, module_id, 0, 0xF244 | 1, (uintptr_t *)&TinyPartitionFreeMemBlock);
	if(res < 0){
		return res;
	}

	res = module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, module_id, 0, 0xF4E8 | 1, (uintptr_t *)&TinyPartitionAllocMemBlockRaw);
	if(res < 0){
		return res;
	}

	res = module_get_offset(SCE_GUID_KERNEL_PROCESS_ID, module_id, 0, 0x1FF20 | 1, (uintptr_t *)&sceKernelSysrootPIDtoAddressSpaceCB);
	if(res < 0){
		return res;
	}

	return 0;
}


MmapProcess *g_process_list;
SceUID mmap_heapid;
SceUID global_mutex;
int global_lock; // for g_process_list lookup/update


int mmap_process_clean(SceUID pid){

	MmapProcess *mp, **process_list;

	int prev = ksceKernelCpuSuspendIntr(&global_lock);

	process_list = &(g_process_list);

	while((*process_list) != NULL){
		if(pid == (*process_list)->pid){
			mp = (*process_list)->next;
			ksceKernelFreeHeapMemory(mmap_heapid, *process_list);
			*process_list = mp;
			ksceKernelCpuResumeIntr(&global_lock, prev);
			return 0;
		}

		process_list = &((*process_list)->next);
	}

	ksceKernelCpuResumeIntr(&global_lock, prev);

	return -1;
}

MmapProcess *mmap_get_process(SceUID pid){

	MmapProcess *mp;

	int prev = ksceKernelCpuSuspendIntr(&global_lock);

	mp = g_process_list;

	while(mp != NULL){
		if(mp->pid == pid){
			ksceKernelCpuResumeIntr(&global_lock, prev);
			return mp;
		}

		mp = mp->next;
	}

	ksceKernelCpuResumeIntr(&global_lock, prev);

	return NULL;
}

MmapContext *mmap_search_cb(MmapProcess *mp, SceUIntPtr addr){

	MmapContext *mmap_ctx = mp->mmap_ctx;
	while(mmap_ctx != NULL){
		if((addr - (SceUIntPtr)mmap_ctx->addr) < mmap_ctx->length){
			return mmap_ctx;
		}
		mmap_ctx = mmap_ctx->next;
	}

	return NULL;
}

int mmap_core(void *addr, size_t length, int prot, MmapParam *param){

	int res;
	SceUID pid, fd;
	SceIoStat stat;
	MmapProcess *mp;
	MmapContext *mmap_ctx;
	SceUIDAddressSpaceObject *pAddressSpaceObject;
	SceUIDPartitionObject *pPart;

	if((((SceUIntPtr)addr) & 0xFFF) != 0 || length == 0 || (length & 0xFFF) != 0){
		return -1;
	}

	if((prot & PROT_EXEC) != 0){
		ksceDebugPrintf("%s: PROT_EXEC is unsupported\n", __FUNCTION__);
		return -1;
	}

	if(prot != PROT_NONE && (prot & PROT_READ) == 0){
		ksceDebugPrintf("%s: PROT_READ is missing. it required.\n", __FUNCTION__);
		return -1;
	}

	if((param->flags & MAP_ANONYMOUS) != 0){
		ksceDebugPrintf("%s: MAP_ANONYMOUS is unsupported\n", __FUNCTION__);
		return -1;
	}

	if((param->flags & MAP_PRIVATE) != 0){
		ksceDebugPrintf("%s: MAP_PRIVATE is unsupported\n", __FUNCTION__);
		return -1;
	}

	if((param->flags & MAP_SHARED) == 0 && (prot & PROT_WRITE) != 0){
		ksceDebugPrintf("%s: MAP_SHARED is missing with PROT_WRITE prot. it required.\n", __FUNCTION__);
		return -1;
	}

	pid = ksceKernelGetProcessId();
	if(pid < 0){
		return pid;
	}

	res = sceKernelSysrootPIDtoAddressSpaceCB(pid, &pAddressSpaceObject);
	if(res < 0){
		ksceDebugPrintf("%s: sceKernelSysrootPIDtoAddressSpaceCB failed 0x%X for 0x%X\n", __FUNCTION__, res, pid);
		return res;
	}

	if(param->fd != -1){
		fd = kscePUIDtoGUID(pid, param->fd);
		if(fd < 0){
			return fd;
		}

		res = ksceIoGetstatByFd(fd, &stat);
		if(res < 0){
			return res;
		}
	}else{
		fd = param->fd;
	}

	ksceKernelLockMutex(global_mutex, 1, NULL);

	mp = mmap_get_process(pid);
	if(mp == NULL){
		ksceDebugPrintf("%s: mmap_get_process failed for 0x%X\n", __FUNCTION__, pid);
		ksceKernelUnlockMutex(global_mutex, 1);
		return -1;
	}

	int prev = ksceKernelCpuSuspendIntr(&(mp->lock));

	mmap_ctx = ksceKernelAllocHeapMemory(mmap_heapid, sizeof(*mmap_ctx));
	if(mmap_ctx == NULL){
		ksceDebugPrintf("%s: sceKernelAllocHeapMemory failed\n", __FUNCTION__);
		ksceKernelCpuResumeIntr(&(mp->lock), prev);
		ksceKernelUnlockMutex(global_mutex, 1);
		return -1;
	}

	memset(mmap_ctx, 0, sizeof(*mmap_ctx));

	SceKernelBlock *a4;
	SceKernelAllocMemBlockCommand cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.size = length;

	if(addr == NULL){
		pPart = pAddressSpaceObject->pProcAS[12];
		res = TinyPartitionAllocMemBlockRaw(pPart, &cmd, length, &a4);
		if(res < 0){
			ksceKernelFreeHeapMemory(mmap_heapid, mmap_ctx);
			ksceKernelCpuResumeIntr(&(mp->lock), prev);
			ksceKernelUnlockMutex(global_mutex, 1);
			return res;
		}

		mmap_ctx->memtype = SCE_KERNEL_MEMBLOCK_TYPE_USER_RW;
	}else{

		pPart = NULL;

		for(int i=0;i<32;i++){
			if(pAddressSpaceObject->pProcAS[i] == NULL){
				continue;
			}

			if(pAddressSpaceObject->pProcAS[i]->pid != pid){
				continue;
			}

			if(length > pAddressSpaceObject->pProcAS[i]->tiny.base_size){
				continue;
			}

			if((addr - pAddressSpaceObject->pProcAS[i]->tiny.base_vaddr) >= pAddressSpaceObject->pProcAS[i]->tiny.base_size){
				continue;
			}

			if(((addr + length) - pAddressSpaceObject->pProcAS[i]->tiny.base_vaddr) >= pAddressSpaceObject->pProcAS[i]->tiny.base_size){
				continue;
			}

			if(strcmp(pAddressSpaceObject->pProcAS[i]->tiny.name, "SceKernelUserCdram") == 0){
				continue;
			}

			if(strcmp(pAddressSpaceObject->pProcAS[i]->tiny.name, "SceKernelUserCDialogNC") == 0){
				continue;
			}

			if(strcmp(pAddressSpaceObject->pProcAS[i]->tiny.name, "SceKernelUserIO") == 0){
				continue;
			}

			if(strcmp(pAddressSpaceObject->pProcAS[i]->tiny.name, "SceKernelUserCDialog") == 0){
				continue;
			}

			if(strcmp(pAddressSpaceObject->pProcAS[i]->tiny.name, "SceKernelUserShared") == 0){
				continue;
			}

			pPart = pAddressSpaceObject->pProcAS[i];
			break;
		}

		if(pPart == NULL){
			ksceKernelFreeHeapMemory(mmap_heapid, mmap_ctx);
			ksceKernelCpuResumeIntr(&(mp->lock), prev);
			ksceKernelUnlockMutex(global_mutex, 1);
			return -1;
		}

		if(strcmp(pPart->tiny.name, "SceKernelUserUncache") == 0){
			mmap_ctx->memtype = SCE_KERNEL_MEMBLOCK_TYPE_USER_RW_UNCACHE;
		}else if(strcmp(pPart->tiny.name, "SceKernelUserMain") == 0){
			mmap_ctx->memtype = SCE_KERNEL_MEMBLOCK_TYPE_USER_RW;
		}else if(strcmp(pPart->tiny.name, "SceKernelUserTool") == 0){
			mmap_ctx->memtype = SCE_KERNEL_MEMBLOCK_TYPE_USER_TOOL_RW;
		}else{
			ksceDebugPrintf("unknown part name (%s)\n", pPart->tiny.name);
			ksceKernelFreeHeapMemory(mmap_heapid, mmap_ctx);
			ksceKernelCpuResumeIntr(&(mp->lock), prev);
			ksceKernelUnlockMutex(global_mutex, 1);
			return -1;
		}

		PartitionAllocMemBlockInListByAddrByCommandRaw(pPart, &cmd, (SceUIntPtr)addr);
		a4 = cmd.pBlock;
	}

	a4->memtype = MMAP_DUMMY_MEMTYPE;

	MmapBlock *mb;

	mb = ksceKernelAllocHeapMemory(mmap_heapid, sizeof(*mb));
	mb->next = NULL;
	mb->prev = NULL;
	mb->pBlock = a4;
	mb->vbase = a4->vbase;
	mb->vsize = length;
	mb->memid = -1;

	mmap_ctx->next      = mp->mmap_ctx;
	mmap_ctx->addr      = (void *)a4->vbase;
	mmap_ctx->length    = length;
	mmap_ctx->offset    = param->offset;
	mmap_ctx->fd        = fd;
	mmap_ctx->prot      = prot;
	mmap_ctx->flags     = param->flags;
	mmap_ctx->pPart     = pPart;
	mmap_ctx->pMmapBlock = mb;

	mp->mmap_ctx = mmap_ctx;

	param->result = (void *)a4->vbase;

	ksceKernelCpuResumeIntr(&(mp->lock), prev);
	ksceKernelUnlockMutex(global_mutex, 1);

	return 0;
}

int munmap_core(SceUID pid, void *addr, size_t length){

	MmapProcess *mp;
	MmapContext *mmap_ctx1, *mmap_ctx2;

	ksceKernelLockMutex(global_mutex, 1, NULL);

	mp = mmap_get_process(pid);
	if(mp == NULL){
		ksceDebugPrintf("%s: munmap failed for 0x%X\n", __FUNCTION__, pid);
		ksceKernelUnlockMutex(global_mutex, 1);
		return 0x80000000;
	}

	int prev = ksceKernelCpuSuspendIntr(&(mp->lock));

	mmap_ctx1 = mmap_search_cb(mp, (SceUIntPtr)addr);
	if(mmap_ctx1 == NULL){
		// ksceDebugPrintf("%s: not found mmap CB for 0x%X\n", __FUNCTION__, addr);
		ksceKernelCpuResumeIntr(&(mp->lock), prev);
		ksceKernelUnlockMutex(global_mutex, 1);
		return 0x80000000;
	}

	mmap_ctx2 = mmap_search_cb(mp, ((SceUIntPtr)addr) + length - 1);
	if(mmap_ctx2 == NULL){
		// ksceDebugPrintf("%s: not found mmap CB for 0x%X\n", __FUNCTION__, ((SceUIntPtr)addr) + length - 1);
		ksceKernelCpuResumeIntr(&(mp->lock), prev);
		ksceKernelUnlockMutex(global_mutex, 1);
		return 0x80000000;
	}

	if(mmap_ctx1 != mmap_ctx2){
		ksceDebugPrintf("%s: invalid munmap range : %p 0x%X\n", __FUNCTION__, addr, length);
		ksceDebugPrintf("\tmmap_ctx1: %p addr=%p length=0x%08X\n", mmap_ctx1, mmap_ctx1->addr, mmap_ctx1->length);
		ksceDebugPrintf("\tmmap_ctx2: %p addr=%p length=0x%08X\n", mmap_ctx2, mmap_ctx2->addr, mmap_ctx2->length);
		ksceKernelCpuResumeIntr(&(mp->lock), prev);
		ksceKernelUnlockMutex(global_mutex, 1);
		return 0x80000000;
	}

	if(mmap_ctx1->addr != addr || mmap_ctx1->length != length){
		ksceDebugPrintf("Partly munmap is not supported.\n");
		ksceDebugPrintf("\tMapping: %p 0x%X\n", mmap_ctx1->addr, mmap_ctx1->length);
		ksceDebugPrintf("\tRequest: %p 0x%X\n", addr, length);
		ksceKernelCpuResumeIntr(&(mp->lock), prev);
		ksceKernelUnlockMutex(global_mutex, 1);
		return 0x80000000;
	}

	MmapBlock *pMmapBlock = mmap_ctx1->pMmapBlock;

	while(pMmapBlock != NULL){

		MmapBlock *next = pMmapBlock->next;

		ksceDebugPrintf("%s: fragment %p 0x%X\n", __FUNCTION__, pMmapBlock->vbase, pMmapBlock->vsize);

		if(pMmapBlock->pBlock != NULL){
			ksceDebugPrintf("%s: There pBlock reserved (%p)\n", __FUNCTION__, pMmapBlock->pBlock);
			TinyPartitionFreeMemBlock(mmap_ctx1->pPart, pMmapBlock->pBlock, 0, TinyPartitionFreeMemBlockCallback);
		}

		if(pMmapBlock->memid > 0){
			// ksceKernelCpuDcacheAndL2WritebackRange((void *)pMmapBlock->vbase, pMmapBlock->vsize);
			asm volatile ("dmb sy\n":::"memory");
			asm volatile ("dsb sy\n":::"memory");
			asm volatile ("isb sy\n":::"memory");
			// ksceKernelCpuDcacheAndL2InvalidateRange((void *)pMmapBlock->vbase, pMmapBlock->vsize);
			asm volatile ("dmb sy\n":::"memory");
			asm volatile ("dsb sy\n":::"memory");
			asm volatile ("isb sy\n":::"memory");

			if((mmap_ctx1->prot & PROT_WRITE) != 0 && pMmapBlock->has_data != 0){

				void *kernel_page = NULL;
				SceSize kernel_size = 0;
				SceUInt32 kernel_offset = 0;

				SceUID usermap = ksceKernelUserMap("MmapUserIO", 1, (void *)pMmapBlock->vbase, pMmapBlock->vsize, &kernel_page, &kernel_size, &kernel_offset);

				ksceKernelCpuResumeIntr(&(mp->lock), prev);
				ksceIoPwrite(mmap_ctx1->fd, kernel_page + kernel_offset, pMmapBlock->vsize, mmap_ctx1->offset + (((void *)pMmapBlock->vbase) - mmap_ctx1->addr));
				prev = ksceKernelCpuSuspendIntr(&(mp->lock));

				ksceKernelMemBlockRelease(usermap);
			}

			ksceDebugPrintf("%s: There memblock allocate (0x%X)\n", __FUNCTION__, pMmapBlock->memid);
			ksceKernelFreeMemBlock(pMmapBlock->memid);
		}

		ksceKernelFreeHeapMemory(mmap_heapid, pMmapBlock);

		pMmapBlock = next;
	}

	MmapContext **mmap_ctx = &(mp->mmap_ctx);
	while((*mmap_ctx) != NULL){
		if((*mmap_ctx) == mmap_ctx1){
			*mmap_ctx = mmap_ctx1->next;
			ksceKernelFreeHeapMemory(mmap_heapid, mmap_ctx1);
			break;
		}
		mmap_ctx = &((*mmap_ctx)->next);
	}

	ksceKernelCpuResumeIntr(&(mp->lock), prev);
	ksceKernelUnlockMutex(global_mutex, 1);

	return 0;
}

int mmap_proc_create(SceUID pid, SceProcEventInvokeParam2 *a2, int a3){

	MmapProcess *mp;

	mp = ksceKernelAllocHeapMemory(mmap_heapid, sizeof(*mp));

	int prev = ksceKernelCpuSuspendIntr(&global_lock);
	mp->next     = g_process_list;
	mp->pid      = pid;
	mp->mmap_ctx = NULL;

	g_process_list = mp;
	ksceKernelCpuResumeIntr(&global_lock, prev);

	return 0;
}

int munmap_process_all(SceUID pid){

	MmapProcess *mp;
	SceUIDAddressSpaceObject *pAddressSpaceObject;

	sceKernelSysrootPIDtoAddressSpaceCB(pid, &pAddressSpaceObject);

	mp = mmap_get_process(pid);
	if(mp != NULL){

		SceKernelProcessContext mmu_ctx;

		ksceKernelCpuSaveContext(&mmu_ctx);
		ksceKernelCpuRestoreContext(&(pAddressSpaceObject->unk_0x18->cpu_ctx));
		while(mp->mmap_ctx != NULL){
			ksceDebugPrintf("process munmap: %p 0x%X\n", mp->mmap_ctx->addr, mp->mmap_ctx->length);
			munmap_core(pid, mp->mmap_ctx->addr, mp->mmap_ctx->length);
		}
		ksceKernelCpuRestoreContext(&mmu_ctx);
	}

	return 0;
}

int mmap_proc_exit(SceUID pid, SceProcEventInvokeParam1 *a2, int a3){

	munmap_process_all(pid);
	mmap_process_clean(pid);

	return 0;
}

int mmap_proc_kill(SceUID pid, SceProcEventInvokeParam1 *a2, int a3){

	munmap_process_all(pid);
	mmap_process_clean(pid);

	return 0;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize args, void *argp){

	global_mutex = ksceKernelCreateMutex("MmapMutex", 0, 1, NULL);

	SceProcEventHandler handler;
	handler.size           = sizeof(handler);
	handler.create         = mmap_proc_create;
	handler.exit           = mmap_proc_exit;
	handler.kill           = mmap_proc_kill;
	handler.stop           = NULL;
	handler.start          = NULL;
	handler.switch_process = NULL;

	ksceKernelRegisterProcEventHandler("MmapProcEvent", &handler, 0);

	mmap_heapid = ksceKernelCreateHeap("MmapHeap", 0x8000, NULL);

	ksceExcpmgrRegisterHandler(SCE_EXCP_DABT, 0, mmap_dabt_handler);

	prog_start();

	return SCE_KERNEL_START_SUCCESS;
}
