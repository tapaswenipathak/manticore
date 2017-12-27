ARCH ?= $(shell uname -m)

include arch/$(ARCH)/Makefile
include lib/libc/Makefile

LD := ld.bfd

includes += -include include/kernel/kernel.h -Iinclude

objs += kernel/init.o
objs += kernel/panic.o
objs += kernel/printf.o
objs += kernel/syscall.o
objs += kernel/thread.o
objs += mm/kmem.o

rust_src += drivers/pci/lib.rs
rust_src += kernel/elf.rs
rust_src += kernel/lib.rs
rust_src += kernel/memory.rs
rust_src += kernel/print.rs
rust_src += manticore.rs

ifdef TEST
CFLAGS += -DHAVE_TEST
tests += tests/tst-kmem.o
tests += tests/tst-page-alloc.o
endif

WARNINGS = -Wall -Wextra -Wno-unused-parameter
CFLAGS += -std=gnu11 -O3 -g $(WARNINGS) -ffreestanding $(includes)
ASFLAGS += -D__ASSEMBLY__ $(includes)
LDFLAGS += --gc-sections

LIBMANTICORE=target/$(ARCH)-unknown-none/release/libmanticore.a

DEPS=.deps
$(objs): | $(DEPS)
$(DEPS):
	mkdir -p $(DEPS)

kernel.elf: arch/$(ARCH)/kernel.ld $(objs) $(LIBMANTICORE) $(tests)
	$(CROSS_PREFIX)$(LD) $(LDFLAGS) -Tarch/$(ARCH)/kernel.ld $(objs) $(LIBMANTICORE) $(tests) -o $@ -Ltarget/$(ARCH)-unknown-none/release -lmanticore

$(LIBMANTICORE): $(rust_src)
	CC=$(CROSS_PREFIX)gcc RUST_TARGET_PATH=$(PWD) xargo build --release --verbose --target $(ARCH)-unknown-none

%.o: %.c
	$(CROSS_PREFIX)gcc $(CFLAGS) -MD -c -o $@ $< -MF $(DEPS)/$(notdir $*).d

%.o: %.S
	$(CROSS_PREFIX)gcc $(ASFLAGS) -MD -c $< -o $@ -MF $(DEPS)/$(notdir $*).d

%.ld: %.ld.S
	$(CROSS_PREFIX)cpp $(CFLAGS) -P $< $@

clean:
	rm -f kernel.elf $(objs) $(tests)
	rm -f arch/$(ARCH)/kernel.ld
	rm -rf target
	rm -rf $(DEPS)

.PHONY: all clean

-include $(DEPS)/*.d
