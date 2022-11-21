
#ifndef _MMAP_USER_H_
#define _MMAP_USER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <psp2common/types.h>



#define PROT_READ  (0x1)                /* Page can be read.  */
#define PROT_WRITE (0x2)                /* Page can be written.  */
#define PROT_EXEC  (0x4)                /* Page can be executed.  */
#define PROT_NONE  (0x0)                /* Page can not be accessed.  */


#define MAP_SHARED    (0x01)                /* Share changes.  */
#define MAP_PRIVATE   (0x02)                /* Changes are private.  */

#define MAP_ANONYMOUS (0x20)                /* Don't use a file.  */


typedef struct MmapParam {
	int flags;
	int fd;
	SceOff offset;
	void *result;
} MmapParam;


int mmap_for_user(void *addr, size_t length, int prot, MmapParam *param);

int munmap(void *addr, size_t length);


#ifdef __cplusplus
}
#endif

#endif /* _MMAP_USER_H_ */
