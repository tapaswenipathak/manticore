#include <kernel/cpu.h>
#include <kernel/panic.h>

static cpuid_cache_t cache = {
    .initialized = 0
};

static int cpu_emt64_enable(void)
{
    uint32_t efer;

    efer = ia32_rdmsr(IA32_EFER);
    return efer & 0x400;
}

static int cpu_nx_enable(void)
{
    uint32_t efer;

    efer = ia32_rdmsr(IA32_EFER);
    return efer & 0x800;
}

bool cpu_has_feature(uint32_t feature)
{
    if (!cache.initialized) {
		        cpuid_host_init(&cache);
		    }
    return cpuid_host_has_feature(&cache, feature);
}

void arch_halt_cpu(void)
{
	asm volatile (
		"hlt"
		:
		:
		: "memory");
}
