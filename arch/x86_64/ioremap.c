#include <kernel/mmu.h>

#include <kernel/page-alloc.h>
#include <kernel/align.h>

#include <stddef.h>

#define MAX_IOREMAP_ENTRIES 20

struct ioremap_table {
	unsigned long real_map_addr;
	unsigned long ioremap_addr;
	unsigned long phys_addr;
	unsigned long size;
};

static struct ioremap_table io_table[MAX_IOREMAP_ENTRIES];
static int ioremap_table_initialized = 0;

///
/// Kernel virtual memory end address.
///
/// The ioremap() function uses this address to allocate virtual memory for I/O memory maps.
///
virt_t kernel_vm_end;

///
/// Map an I/O memory region to kernel virtual address space.
///
/// This function maps an I/O memory region to virtual address space so that the I/O memory region can be accessed by
/// the kernel.
///
/// \param paddr I/O memory region start address.
/// \param size I/O memory region size.
/// \return I/O memory region start address in virtual address space.
///
void *ioremap(phys_t io_mem_start, size_t io_mem_size)
{
	virt_t ret = kernel_vm_end;
	kernel_vm_end += align_up(io_mem_size, PAGE_SIZE_SMALL);
	mmu_map_t map = mmu_current_map();
	int err = mmu_map_range(map, ret, io_mem_start, io_mem_size, MMU_PROT_READ | MMU_PROT_WRITE, MMU_NOCACHE);
	if (err) {
		return NULL;
	}
	return (void *)ret;
}


static int set_ioremap_entry(unsigned long real_map_addr,
                             unsigned long ioremap_addr,
			     unsigned long phys_addr,
			     unsigned long size)
{
	int i;

	spin_lock(&ioremap_lock);

	if (!ioremap_table_initialized)
		init_ioremap_nocheck();

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].real_map_addr == 0) {
			io_table[i] = (struct ioremap_table){real_map_addr,
			                                     ioremap_addr,
			                                     phys_addr,
			                                     size};
			spin_unlock(&ioremap_lock);
			return 0;
		}

	spin_unlock(&ioremap_lock);
	printk("no free entry in ioremaptable\n");
	BUG();
	return 1;
}

static int __lookup_ioremap_entry_phys(unsigned long phys_addr)
{
	int i;

	if (!ioremap_table_initialized)
		return -1;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if ((io_table[i].phys_addr <= phys_addr) &&
		    io_table[i].phys_addr + io_table[i].size > phys_addr)
			break;

	spin_unlock(&ioremap_lock);
	return i == MAX_IOREMAP_ENTRIES ? -1 : i;
}

unsigned long find_ioremap_entry(unsigned long phys_addr)
{
	int i;
	if ((i = __lookup_ioremap_entry_phys(phys_addr)) == -1)
		return 0;

	return io_table[i].ioremap_addr + (phys_addr - io_table[i].phys_addr);
}

static int remove_ioremap_entry_phys(unsigned long phys_addr)
{
	int i;
	if ((i = __lookup_ioremap_entry_phys(phys_addr)) == -1)
		return -1;

	spin_lock(&ioremap_lock);
	reset_ioremap_entry_nocheck(i);
	spin_unlock(&ioremap_lock);
	return 0;
}

#ifdef CONFIG_L4
static unsigned long lookup_phys_entry(unsigned long ioremap_addr,
                                       unsigned long *size)
{
	int i;

	if (!ioremap_table_initialized)
		return 0;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].ioremap_addr == ioremap_addr) {
			*size = io_table[i].size;
			spin_unlock(&ioremap_lock);
			return io_table[i].phys_addr;
		}

	spin_unlock(&ioremap_lock);
	return 0;
}

static inline unsigned long get_iotable_entry_size(int i)
{
	return io_table[i].size;
}

static inline unsigned long get_iotable_entry_ioremap_addr(int i)
{
	return io_table[i].ioremap_addr;
}

static inline unsigned long get_iotable_entry_phys(int i)
{
	return io_table[i].phys_addr;
}

#else

static unsigned long lookup_ioremap_entry(unsigned long ioremap_addr)
{
	int i;
	unsigned long result = 0;

	if (!ioremap_table_initialized)
		return 0;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].ioremap_addr == ioremap_addr) {
			result = io_table[i].real_map_addr;
			break;
		}

	spin_unlock(&ioremap_lock);
	return result;
}

static inline void remap_area_pte(pte_t * pte, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;
	unsigned long pfn;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	if (address >= end)
		BUG();
	pfn = phys_addr >> PAGE_SHIFT;
	do {
		if (!pte_none(*pte)) {
			printk("remap_area_pte: page already exists\n");
			BUG();
		}
		set_pte(pte, pfn_pte(pfn, __pgprot(_PAGE_PRESENT | _PAGE_RW |
					_PAGE_DIRTY | _PAGE_ACCESSED | flags)));
		address += PAGE_SIZE;
		pfn++;
		pte++;
	} while (address && (address < end));
}

static inline int remap_area_pmd(pmd_t * pmd, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	phys_addr -= address;
	if (address >= end)
		BUG();
	do {
		pte_t * pte = pte_alloc_kernel(pmd, address);
		if (!pte)
			return -ENOMEM;
		remap_area_pte(pte, address, end - address, address + phys_addr, flags);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

static int remap_area_pages(unsigned long address, unsigned long phys_addr,
				 unsigned long size, unsigned long flags)
{
	int error;
	pgd_t * dir;
	unsigned long end = address + size;

	phys_addr -= address;
	dir = pgd_offset(&init_mm, address);
	flush_cache_all();
	if (address >= end)
		BUG();
	do {
		pud_t *pud;
		pmd_t *pmd;

		error = -ENOMEM;
		pud = pud_alloc(&init_mm, dir, address);
		if (!pud)
			break;
		pmd = pmd_alloc(&init_mm, pud, address);
		if (!pmd)
			break;
		if (remap_area_pmd(pmd, address, end - address,
					 phys_addr + address, flags))
			break;
		error = 0;
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	flush_tlb_all();
	return error;
}

