#ifndef HAX_CORE_IA32_H_
#define HAX_CORE_IA32_H_

#include "../../include/hax_types.h"

union cpuid_args_t;
struct system_desc_t;

mword ASMCALL get_cr0(void);
mword ASMCALL get_cr2(void);
mword ASMCALL get_cr3(void);
mword ASMCALL get_cr4(void);
mword ASMCALL get_dr0(void);
mword ASMCALL get_dr1(void);
mword ASMCALL get_dr2(void);
mword ASMCALL get_dr3(void);
mword ASMCALL get_dr6(void);
mword ASMCALL get_dr7(void);

void ASMCALL set_cr0(mword val);
void ASMCALL set_cr2(mword val);
void ASMCALL set_cr3(mword val);
void ASMCALL set_cr4(mword val);
void ASMCALL set_dr0(mword val);
void ASMCALL set_dr1(mword val);
void ASMCALL set_dr2(mword val);
void ASMCALL set_dr3(mword val);
void ASMCALL set_dr6(mword val);
void ASMCALL set_dr7(mword val);

uint16_t ASMCALL get_kernel_cs(void);
uint16_t ASMCALL get_kernel_ds(void);
uint16_t ASMCALL get_kernel_es(void);
uint16_t ASMCALL get_kernel_ss(void);
uint16_t ASMCALL get_kernel_gs(void);
uint16_t ASMCALL get_kernel_fs(void);

void ASMCALL set_kernel_ds(uint16_t val);
void ASMCALL set_kernel_es(uint16_t val);
void ASMCALL set_kernel_gs(uint16_t val);
void ASMCALL set_kernel_fs(uint16_t val);

void ASMCALL asm_btr(uint8_t *addr, uint bit);
void ASMCALL asm_bts(uint8_t *addr, uint bit);
void ASMCALL asm_clts(void);
void ASMCALL asm_fxinit(void);
void ASMCALL asm_fxsave(mword *addr);
void ASMCALL asm_fxrstor(mword *addr);
void ASMCALL asm_cpuid(union cpuid_args_t *state);

void ASMCALL __nmi(void);
uint32_t ASMCALL asm_fls(uint32_t bit32);

uint64_t ia32_rdmsr(uint32_t reg);
void ia32_wrmsr(uint32_t reg, uint64_t val);

uint64_t ia32_rdtsc(void);

void hax_clts(void);

void hax_fxinit(void);
void hax_fxsave(mword *addr);
void hax_fxrstor(mword *addr);

void btr(uint8_t *addr, uint bit);
void bts(uint8_t *addr, uint bit);

void ASMCALL asm_enable_irq(void);
void ASMCALL asm_disable_irq(void);

uint64_t ASMCALL get_kernel_rflags(void);
uint16_t ASMCALL get_kernel_tr_selector(void);

void ASMCALL set_kernel_gdt(struct system_desc_t *sys_desc);
void ASMCALL set_kernel_idt(struct system_desc_t *sys_desc);
void ASMCALL set_kernel_ldt(uint16_t sel);
void ASMCALL get_kernel_gdt(struct system_desc_t *sys_desc);
void ASMCALL get_kernel_idt(struct system_desc_t *sys_desc);
uint16_t ASMCALL get_kernel_ldt(void);

#endif  // HAX_CORE_IA32_H_
