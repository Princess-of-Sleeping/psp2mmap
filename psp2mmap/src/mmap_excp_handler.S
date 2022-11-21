
	.balign 0x10
	.text
	.cpu cortex-a9
	.arch armv7-a
	.syntax unified
	.arm
	.fpu neon


.macro enter_mmap_excp
	sub sp, sp, #8
	push {r0, r1, r2, r3, ip, lr}
	sub sp, sp, #0x20

	// setup jump context
	sub        r0, lr, #8
	str        r0, [sp, #0x38] // PC
	mrs        r0, cpsr
	str        r0, [sp, #0x3C] // CPSR
.endm

.macro leave_mmap_excp
	add        sp, #0x20
	pop        {r0, r1, r2, r3, ip, lr}
	rfeia      sp!
.endm


	.globl mmap_dabt_handler
	.type  mmap_dabt_handler, %function

mmap_dabt_handler:
	.word 0
	.word 0

	enter_mmap_excp

	mrs        r0, spsr

	and        r0, #0x1F
	cmp        r0, #0x10
	bne        continue_dabt_process // mmap is usermode only

	str        r0, [sp] // save spsr

	mov        r3, sp

	cps        #0x1F

	mov        r2, sp // save usermode sp

	mrc        p15, #0, r1, c13, c0, #3 // TPIDRURO
	str        r1, [r3, #0x4] // save

	// setting kernel stack
	mrc        p15, #0, r1, c13, c0, #4 // TPIDRPRW
	ldr        sp, [r1, #0x30] // setting kernel stack

	// setting syscall frame
	//   SceUInt32 reg[0xD];
	//   SceUInt32 unk_0x34; // unknown
	//   SceUInt32 unk_0x38; // syscall entry pointer
	//   SceUInt32 fpscr;
	//   SceUInt32 unk_0x40; // syscall option
	//   SceUInt32 unk_0x44; // TPIDRURW
	//   SceUInt32 unk_0x48; // unused?
	//   SceUInt32 unk_0x4C; // unused?
	//   SceUInt32 sp;
	//   SceUInt32 lr;
	//   SceUInt32 pc;
	//   SceUInt32 cpsr;
	sub        sp, #0x60
	str        sp, [r1, #0x44]

	str        r2, [sp, #0x50]
	str        lr, [sp, #0x54]

	ldr        r2, [r3, #0x38]
	ldr        lr, [r3]
	str        r2, [sp, #0x58]
	str        lr, [sp, #0x5C]

	movs       r2, #0
	vmrs       lr, fpscr
	str        r2, [sp, #0x38]
	str        lr, [sp, #0x3C]

	ldr        r0, [sp, #0x50] // get abt mode sp
	add        r0, #0x28
	ldm        r0, {r0, r1, r2, r3}
	stm        sp, {r0, r1, r2, r3, r4, r5, r6, r7, r8, sb, sl, fp, ip}

	movs       r3, #0
	mrc        p15, #0, r2, c13, c0, #2 // TPIDRURW
	str        r3, [sp, #0x40]
	str        r2, [sp, #0x44]

	// some syscall setting
	movs       r2, #1
	mcr        p15, #0, r2, c13, c0, #3 // TPIDRURO

	vpush      {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15}
	vpush      {d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31}

	cpsie      i
	mrc        p15, #0, r0, c6, c0, #0 // DFAR
	mov        r1, sp
	blx        excp_handler_cfunc
	cpsid      i

	vpop       {d16, d17, d18, d19, d20, d21, d22, d23, d24, d25, d26, d27, d28, d29, d30, d31}
	vpop       {d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15}

	mrc        p15, #0, r1, c13, c0, #4 // TPIDRPRW
	movs       r2, #0
	str        r2, [r1, #0x44]

	ldr        r1, [sp, #0x3C]
	vmsr       fpscr, r1

	ldr        lr, [sp, #0x54]
	ldr        sp, [sp, #0x50]

	cps        #0x17 // return to abt

	ldr        r1, [sp, #0x4]
	mcr        p15, #0, r1, c13, c0, #3

	cmp        r0, #0
	beq        continue_dabt_process

	mrs        r0, spsr // load spsr of DABT mode
	str        r0, [sp, #0x3C] // CPSR

	leave_mmap_excp

continue_dabt_process:
	movw       r0, #:lower16:mmap_dabt_handler
	movt       r0, #:upper16:mmap_dabt_handler
	ldr        r0, [r0]
	add        r0, r0, #0x8
	str        r0, [sp, #0x38] // PC

	leave_mmap_excp


	.data
