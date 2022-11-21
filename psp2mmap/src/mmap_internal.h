
#ifndef _MMAP_INTERNAL_H_
#define _MMAP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <psp2common/types.h>
#include "sysmem_internal.h"
#include "../../mmap_user.h"


#define MMAP_PAGE_SIZE (0x20000)
#define MMAP_DUMMY_MEMTYPE (0xF1F1F1F1)


typedef struct MmapBlock {
	struct MmapBlock *next;
	struct MmapBlock *prev;
	SceKernelBlock *pBlock;
	SceUIntPtr vbase;
	SceSize    vsize;
	SceUID memid;
	int has_data;
} MmapBlock;

typedef struct MmapCoreMapping {
	MmapBlock *pMmapBlock[2];
	int index;
	int DFAR;
} MmapCoreMapping;

typedef struct MmapContext {
	struct MmapContext *next;
	void *addr;
	int length;
	SceOff offset;
	int fd;
	int prot;
	int flags;
	void *pPart;
	int memtype;
	MmapBlock *pMmapBlock;
	MmapCoreMapping core_mapping[4];
} MmapContext;

typedef struct MmapProcess {
	struct MmapProcess *next;
	SceUID pid;
	int lock;
	MmapContext *mmap_ctx;
} MmapProcess;


MmapProcess *mmap_get_process(SceUID pid);
MmapContext *mmap_search_cb(MmapProcess *mp, SceUIntPtr addr);

int mmap_dabt_handler(void);

int mmap_core(void *addr, size_t length, int prot, MmapParam *param);
int munmap_core(SceUID pid, void *addr, size_t length);



#ifdef __cplusplus
}
#endif

#endif /* _MMAP_INTERNAL_H_ */
