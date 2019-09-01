#ifndef KERNEL_CPU_H
#define KERNEL_CPU_H

enum cpu_feature {
   CPU_FEATURE_NX,
};

void arch_halt_cpu(void);
bool cpu_has_feature(enum cpu_feature feature);
#endif
