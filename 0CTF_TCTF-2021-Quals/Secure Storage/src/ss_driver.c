#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");

//#define DEBUG 1
#define SIMULATION 0


#define DEVICE_NAME "ss"

#define DEVICE_BLOCK_SIZE PAGE_SIZE

#define STORAGE_SLOT_COUNT (16)
#define STORAGE_SLOT_SIZE (16*PAGE_SIZE)

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

//#define BITMAP_TEST(bitmap, index) ( !!( (bitmap)[(index) / (sizeof((bitmap)[0])*8)] & (1 << ((index) % (sizeof((bitmap)[0])*8))) ) )
//#define BITMAP_SET(bitmap, index) ((bitmap)[(index)/(sizeof((bitmap)[0])*8)] |= 1<<((index)%(sizeof((bitmap)[0])*8)))
//#define BITMAP_CLEAR(bitmap, index) ((bitmap)[(index)/(sizeof((bitmap)[0])*8)] &= ~(1<<((index)%(sizeof((bitmap)[0])*8))))
#define BITMAP_TEST(bitmap, index) ( !!( ((unsigned char *)(bitmap))[(index) >> 3] & (1 << ((index) & 7)) ) )
#define BITMAP_SET(bitmap, index) (((unsigned char*)(bitmap))[(index) >> 3] |= 1<<((index) & 7))
#define BITMAP_CLEAR(bitmap, index) (((unsigned char*)(bitmap))[(index) >> 3] &= ~(1<<((index) & 7)))

struct storage_slot_info {
	unsigned long slot_index;
	spinlock_t slot_index_lock;
};

#define storage_cache (global_storage_cache_manager.storage_cache_)
#define storage_cache_page_dirty_bitmap (global_storage_cache_manager.storage_cache_page_dirty_bitmap_)

// page cache and other metadata
// use struct to force them continues in memory !
struct storage_cache_manager_struct {
	__attribute__((aligned(PAGE_SIZE))) unsigned char storage_cache_[STORAGE_SLOT_COUNT][STORAGE_SLOT_SIZE];
	unsigned char storage_cache_page_dirty_bitmap_[STORAGE_SLOT_COUNT*STORAGE_SLOT_SIZE/PAGE_SIZE/sizeof(unsigned char)];
} static global_storage_cache_manager;

static unsigned int storage_slot_reference_count[STORAGE_SLOT_COUNT];
static struct mutex storage_slot_lock[STORAGE_SLOT_COUNT];

// ============================================================================


#if SIMULATION


// simulation of hardware: read/write by block, auto decrypt/encrypt internel rom

// simulation of hardware storage
__attribute__((aligned(DEVICE_BLOCK_SIZE))) static unsigned char storage[STORAGE_SLOT_COUNT*STORAGE_SLOT_SIZE];

#define FEISTEL_K 65536

static unsigned char __initdata zeropage[DEVICE_BLOCK_SIZE];

static void storage_internal_encrypt(void *dst, void *src, unsigned int len) {
	unsigned int i;
	unsigned int j;
	unsigned long long left;
	unsigned long long right;
	unsigned long long oldright;
	for (i = 0; i < len / 16; i++) {
		memcpy(&left, ((unsigned char *)src)+16*i, 8);    // memory may be unaligned
		memcpy(&right, ((unsigned char *)src)+16*i+8, 8);
		for (j = 0; j < FEISTEL_K; j++) {    // feistel
			oldright = right;
			right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
			left = oldright;
		}
		memcpy(((unsigned char *)dst)+16*i, &right, 8);
		memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
	}
}

static void storage_internal_decrypt(void *dst, void *src, unsigned int len) {
	unsigned int i;
	unsigned int j;
	unsigned long long left;
	unsigned long long right;
	unsigned long long oldright;
	for (i = 0; i < len / 16; i++) {
		memcpy(&left, ((unsigned char *)src)+16*i, 8);    // memory may be unaligned
		memcpy(&right, ((unsigned char *)src)+16*i+8, 8);
		for (j = 0; j < FEISTEL_K; j++) {    // feistel
			oldright = right;
			right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
			left = oldright;
		}
		memcpy(((unsigned char *)dst)+16*i, &right, 8);
		memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
	}
}

static void __init zerostorage(void) {
	unsigned long i;
	//unsigned char *zeropage;
	//zeropage = kzalloc(DEVICE_BLOCK_SIZE, GFP_KERNEL);
	//if (zeropage == NULL) {
	//	return;
	//}
	storage_internal_encrypt(((unsigned char *)(&storage))+0*DEVICE_BLOCK_SIZE, zeropage, DEVICE_BLOCK_SIZE);
	//kfree(zeropage);
	for (i = 1; i < STORAGE_SLOT_COUNT*STORAGE_SLOT_SIZE/DEVICE_BLOCK_SIZE; i++) {
		memcpy(((unsigned char *)(&storage))+i*DEVICE_BLOCK_SIZE, &storage, DEVICE_BLOCK_SIZE);
	}
}

static void readblock(unsigned long blocknum, void *buf) {
	// simulation: interact with device
	storage_internal_decrypt(buf, ((unsigned char *)(&storage))+blocknum*DEVICE_BLOCK_SIZE, DEVICE_BLOCK_SIZE);
}

static void writeblock(unsigned long blocknum, void *buf) {
	// simulation: interact with device
	storage_internal_encrypt(((unsigned char *)(&storage))+blocknum*DEVICE_BLOCK_SIZE, buf, DEVICE_BLOCK_SIZE);
}


// -------------------------------------


#else


// https://www.kernel.org/doc/Documentation/PCI/pci.txt

#define QEMU_VENDOR_ID 0x1234
#define SS_DEVICE_ID 0x7373

#define SS_PCI_BAR_MMIO 0


#define SS_MMIO_OFFSET_MAGIC 0x0
#define SS_MMIO_OFFSET_STATUS 0x10
#define SS_MMIO_OFFSET_COMMAND 0x18
#define SS_MMIO_OFFSET_DMA_BLOCKNUM 0x20
#define SS_MMIO_OFFSET_DMA_PHYADDR 0x28

#define SS_STATUS_MASK 0xf
#define SS_SUBSTATUS_MASK 0xf0

#define SS_STATUS_OFF 0x0
#define SS_STATUS_NORMAL 0x1
#define SS_STATUS_BUSY 0x2
#define SS_STATUS_DMA_PREPARE 0x3
#define SS_STATUS_DMA_COMPLETE 0x4
#define SS_SUBSTATUS_DMA_COMPLETE_SUCCESS 0x10
#define SS_SUBSTATUS_DMA_COMPLETE_ERROR 0x20

#define SS_CMD_MASK 0xf
#define SS_SUBCMD_MASK 0xf0

#define SS_CMD_TO_NORMAL 0x1
#define SS_CMD_PREPARE_DMA 0x2
#define SS_CMD_START_DMA 0x3
#define SS_SUBCMD_START_DMA_TO_DEVICE 0x10    // device read, cpu write
#define SS_SUBCMD_START_DMA_FROM_DEVICE 0x20    // device write, cpu read


// real hardware, handle dma and interrupt

static struct pci_dev *ss_pdev; 
static void __iomem *ss_mmio;

// https://www.cnblogs.com/noaming1900/archive/2011/01/14/1935526.html
// https://www.cnblogs.com/zhuyp1015/archive/2012/06/09/2542882.html
// https://www.lenzhao.com/topic/5a5c87d6bedc2a8b075a6058
static DECLARE_WAIT_QUEUE_HEAD(wait_for_device_idle); 
static DECLARE_WAIT_QUEUE_HEAD(wait_for_interrupt);
static bool device_is_idle;
static bool device_irq_occured;

static irqreturn_t irq_handler_0(int irq, void *dev_id) {
#ifdef DEBUG
	printk(KERN_INFO "(irq_handler):  Called\n");
#endif
	device_irq_occured = true;
	wake_up(&wait_for_interrupt);
	return IRQ_HANDLED;
}

static int readwriteblock(unsigned long blocknum, void *buf, bool iswrite) {
	// TODO
	//__attribute__((aligned(4096))) static char b[4096];
	//dma_addr_t daddr = dma_map_page(&(ss_pdev->dev), virt_to_page(b), 0, 4096, 0);
	int result = 0;
	u64 r_status;
	dma_addr_t daddr;
	void *pdaddr;
	int ret;

	// only one process can use the device at same time
	do {
		ret = wait_event_interruptible(wait_for_device_idle, device_is_idle);
		// here, device_is_idle must be true
		// for the first process, the __atomic_exchange_n will set device_is_idle to false and return true, this breaks the while condition
		// but for other processes, the __atomic_exchange_n will set device_is_idle to false and also return false, then start to wait in next loop turn
	} while (!__atomic_exchange_n(&device_is_idle, false, __ATOMIC_RELAXED));
	// signal http://blog.sina.com.cn/s/blog_4770ef020101h45d.html
	if (ret < 0) {    // -ERESTARTSYS
#ifdef DEBUG
		printk(KERN_ERR "readwriteblock: wake up by signal");
#endif
		device_is_idle = true;
		wake_up_interruptible(&wait_for_device_idle);
		result = ret;
		goto finish;
	}
	if (readq(ss_mmio + SS_MMIO_OFFSET_STATUS) != SS_STATUS_NORMAL) {
#ifdef DEBUG
		printk(KERN_ERR "readwriteblock: impossible error !");
#endif
		device_is_idle = true;
		wake_up_interruptible(&wait_for_device_idle);
		result = 1;
		goto finish;		
	}
	writeq(SS_CMD_PREPARE_DMA, ss_mmio + SS_MMIO_OFFSET_COMMAND);

	pdaddr = dma_alloc_coherent(&(ss_pdev->dev), DEVICE_BLOCK_SIZE, &daddr, GFP_KERNEL);
	if (pdaddr == NULL) {
		result = 0;
		goto finish;
	}
	if (iswrite) {
		memcpy(pdaddr, buf, DEVICE_BLOCK_SIZE);
	}
#ifdef DEBUG
	printk(KERN_INFO "readwriteblock test vaddr: %llx, paddr: %llx, busaddr: %llx, daddr: %llx\n", (uint64_t)pdaddr, virt_to_phys(pdaddr), virt_to_bus(pdaddr), daddr);
#endif
	writeq(blocknum, ss_mmio + SS_MMIO_OFFSET_DMA_BLOCKNUM);
	writeq(daddr, ss_mmio + SS_MMIO_OFFSET_DMA_PHYADDR);
	writeq(SS_CMD_START_DMA|(iswrite ? SS_SUBCMD_START_DMA_TO_DEVICE : SS_SUBCMD_START_DMA_FROM_DEVICE), ss_mmio + SS_MMIO_OFFSET_COMMAND);

	device_irq_occured = false;
	wait_event(wait_for_interrupt, device_irq_occured);

	while (1) {
		r_status = readq(ss_mmio + SS_MMIO_OFFSET_STATUS);
		if ((r_status & SS_STATUS_MASK) == SS_STATUS_DMA_COMPLETE) {
			break;
		}
	}

#ifdef DEBUG
	printk(KERN_INFO "readwriteblock result: %llx, %llx, %llx, %llx\n", *(uint64_t *)pdaddr, *(uint64_t *)(pdaddr+8), *(uint64_t *)(pdaddr+16), *(uint64_t *)(pdaddr+24));
#endif
	
	writeq(SS_CMD_TO_NORMAL, ss_mmio + SS_MMIO_OFFSET_COMMAND);
	device_is_idle = true;
	wake_up_interruptible(&wait_for_device_idle);    // wake up extract one waiting proeess

	if ((r_status & SS_SUBSTATUS_MASK) == SS_SUBSTATUS_DMA_COMPLETE_SUCCESS) {
		if (!iswrite) {
			memcpy(buf, pdaddr, DEVICE_BLOCK_SIZE);
		}
		result = 0;
	}
	else {
		result = 1;
	}
	
	dma_free_coherent(&(ss_pdev->dev), DEVICE_BLOCK_SIZE, pdaddr, daddr);
	//dma_unmap_page(&(ss_pdev->dev), daddr, 4096, 0);

finish:
	return result;
}

static int readblock(unsigned long blocknum, void *buf) {
#ifdef DEBUG
	printk(KERN_INFO "readblock: %lx\n", blocknum);
#endif
	return readwriteblock(blocknum, buf, false);
}

static int writeblock(unsigned long blocknum, void *buf) {
#ifdef DEBUG
	printk(KERN_INFO "writeblock: %lx\n", blocknum);
#endif
	return readwriteblock(blocknum, buf, true);
}

#endif


// ============================================================================

static int dev_open(struct inode *inodep, struct file *filep) {
	struct storage_slot_info *info;
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device opened inode %lx file %lx\n", (unsigned long)inodep, (unsigned long)filep);
#endif
	info = (struct storage_slot_info *)kzalloc(sizeof(struct storage_slot_info), GFP_KERNEL);
	if (info == NULL) {
		return -ENOMEM;
	}
	info->slot_index = -1;
	spin_lock_init(&info->slot_index_lock);
	filep->private_data = info;

	return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
	struct storage_slot_info *info;
	unsigned long slot_index;
	unsigned int i;
	unsigned int bitmap_index;
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device released inode %lx file %lx\n", (unsigned long)inodep, (unsigned long)filep);
#endif
	info = (struct storage_slot_info *)filep->private_data;
	spin_lock(&info->slot_index_lock);
	slot_index = info->slot_index;
	spin_unlock(&info->slot_index_lock);
	kfree(info);

#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device released slot_index %lx\n", slot_index);
#endif
	if (slot_index == -1) {
		return 0;
	}

	// write storage_cache back to storage
	mutex_lock(&storage_slot_lock[slot_index]);
	storage_slot_reference_count[slot_index] -= 1;
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device released storage_slot_reference_count %x\n", storage_slot_reference_count[slot_index]);
#endif
	if (storage_slot_reference_count[slot_index] == 0) {
		for (i = 0; i < STORAGE_SLOT_SIZE/PAGE_SIZE; i++) {
			bitmap_index = slot_index*(STORAGE_SLOT_SIZE/PAGE_SIZE)+i;
			if (BITMAP_TEST(storage_cache_page_dirty_bitmap, bitmap_index)) {
				// here, assert PAGE_SIZE == DEVICE_BLOCK_SIZE !!
				if (writeblock(bitmap_index, &storage_cache[slot_index][i*PAGE_SIZE]) != 0) {
#ifdef DEBUG
					printk(KERN_INFO "secure_storage: device released writeblock error\n");
#endif
					mutex_unlock(&storage_slot_lock[slot_index]);
					return -EIO;
				}
				BITMAP_CLEAR(storage_cache_page_dirty_bitmap, bitmap_index);
			}
		}
	}
	mutex_unlock(&storage_slot_lock[slot_index]);

	return 0;
}

static long dev_ioctl(struct file *filep, unsigned int request, unsigned long data) {
	unsigned long slot_index;
	unsigned long old_slot_index;
	struct storage_slot_info *info;
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device ioctl %x %lu\n", request, data);
#endif
	switch (request) {    // ioctl request should have special format. here just ignore it
		//case 0x73706f30:
		case 0:    // TODO change the const
			slot_index = data;
			if (slot_index >= STORAGE_SLOT_COUNT) {
				return -EINVAL;
			}

			info = (struct storage_slot_info *)filep->private_data;
			
			mutex_lock(&storage_slot_lock[slot_index]);
			spin_lock(&info->slot_index_lock);

			old_slot_index = info->slot_index;
			if (old_slot_index != -1) {
				spin_unlock(&info->slot_index_lock);
				mutex_unlock(&storage_slot_lock[slot_index]);
				return -EINVAL;
			}

			if (storage_slot_reference_count[slot_index] == 0xffffffff) {
				spin_unlock(&info->slot_index_lock);
				mutex_unlock(&storage_slot_lock[slot_index]);
				return -EPERM;
			}

			storage_slot_reference_count[slot_index] += 1;
			info->slot_index = slot_index;
			
			spin_unlock(&info->slot_index_lock);
			mutex_unlock(&storage_slot_lock[slot_index]);

			break;
		default:
			return -EINVAL;

	}
	return 0;
}

// -------------------------------------

/*
static void vma_open(struct vm_area_struct *vma) {	
	printk(KERN_INFO "secure_storage: vma_open, virt %lx, phys %lx\n, end %lx\n", vma->vm_start, vma->vm_pgoff << PAGE_SHIFT, vma->vm_end);
}

static void vma_close(struct vm_area_struct *vma) {
	printk(KERN_INFO "secure_storage: vma_close, virt %lx, phys %lx\n, end %lx\n", vma->vm_start, vma->vm_pgoff << PAGE_SHIFT, vma->vm_end);
}
*/

static vm_fault_t vma_fault(struct vm_fault *vmf) {
	int offset;    // XXX vuln, offset should be unsigned
	struct page *page;
	struct vm_area_struct *vma;
	struct file *file;
	struct storage_slot_info *info;
        unsigned long slot_index;
        int bitmap_index;    // it should also better be unsigned

	vma = vmf->vma;
	file = vma->vm_file;
	info = (struct storage_slot_info *)file->private_data;
	slot_index = info->slot_index;    // no need to lock here
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: vma_fault, vma %lx, vma->vm_start %lx, vmf->address %lx, vma->vm_pgoff %lx, slot_index %ld, vmf->flags %x, vmf->cow_page %llx\n", (unsigned long)vma, vma->vm_start, vmf->address, vma->vm_pgoff, info->slot_index, vmf->flags, page_to_phys(vmf->cow_page));
#endif
	offset = ((vmf->address - vma->vm_start) & PAGE_MASK) + (vma->vm_pgoff << PAGE_SHIFT);
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: offset %d, virtual %lx\n", offset, (unsigned long)&storage_cache[slot_index][offset]);
#endif
	if (offset < (int)STORAGE_SLOT_SIZE) {    // XXX vuln, because offset is signed int, it can less than zero
		page = vmalloc_to_page(&storage_cache[slot_index][offset]);
		get_page(page);
		//page = alloc_page(GFP_KERNEL);
	}
	else {
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: VM_FAULT_SIGBUS\n");
#endif
		return VM_FAULT_SIGBUS;
	}
#ifdef DEBUG
	printk(KERN_INFO "                vma_fault offset %lx, kvirt %llx, phys %llx, count %d\n", (unsigned long)offset, (unsigned long long)&storage_cache[info->slot_index][offset], page_to_phys(page), page_ref_count(page));
#endif
	vmf->page = page;

	// prepare data
	mutex_lock(&storage_slot_lock[slot_index]);
	bitmap_index = slot_index * (STORAGE_SLOT_SIZE/PAGE_SIZE) + offset/PAGE_SIZE;
	if (!BITMAP_TEST(storage_cache_page_dirty_bitmap, bitmap_index)) {
#ifdef DEBUG
		printk(KERN_INFO "secure_storage: BITMAP_TEST non present, bitmap_index %d, offset %d, addr %lx\n", bitmap_index, offset, (unsigned long)&storage_cache[slot_index][offset]);
#endif
		// here, assert PAGE_SIZE == DEVICE_BLOCK_SIZE !!
		if (readblock(bitmap_index, &storage_cache[slot_index][offset]) != 0) {
#ifdef DEBUG
			printk(KERN_INFO "secure_storage: readblock error\n");
#endif
			mutex_unlock(&storage_slot_lock[slot_index]);
			return VM_FAULT_SIGBUS;
		}
		BITMAP_SET(storage_cache_page_dirty_bitmap, bitmap_index);
	}
	mutex_unlock(&storage_slot_lock[slot_index]);

#ifdef DEBUG
	printk(KERN_INFO "secure_storage: Success\n");
#endif
	return 0;
}

static struct vm_operations_struct dev_mmap_vm_ops = {
	//.open = vma_open,
	//.close = vma_close,
	.fault = vma_fault,
};

static int dev_mmap(struct file *filep, struct vm_area_struct *vma) {
	struct storage_slot_info *info;
#ifdef DEBUG
	printk(KERN_INFO "secure_storage: device mmap\n");
#endif
	info = (struct storage_slot_info *)filep->private_data;
	spin_lock(&info->slot_index_lock);
	if (info->slot_index == -1) {
		spin_unlock(&info->slot_index_lock);
		return -EPERM;
	}
	spin_unlock(&info->slot_index_lock);

	if (vma->vm_pgoff >= (STORAGE_SLOT_SIZE / PAGE_SIZE)) {    // unsigned long
		return -EINVAL;
	}
	vma->vm_ops = &dev_mmap_vm_ops;
	return 0;
}

/*
static int dev_fsync(struct file *filep, loff_t arg2, loff_t arg3, int datasync) {
	printk(KERN_INFO "secure_storage: device fsync %llx %llx %d\n", arg2, arg3, datasync);
	// write storage_cache back to storage
	return 0;
}
*/

// -------------------------------------

static struct file_operations fileops = {
	.owner = THIS_MODULE,
	.open = dev_open, 
	.release = dev_release, 
	.unlocked_ioctl = dev_ioctl,
	//.compat_ioctl = dev_ioctl,    // ?
	.mmap = dev_mmap,
	//.fsync = dev_fsync,    // for msync and fsync ?
};


// ============================================================================

static struct miscdevice miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &fileops,
	//.mode = 0666,
};


#if SIMULATION

// do nothing

#else

static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id) {
	int r;
#ifdef DEBUG
	printk(KERN_INFO "pci_probe start\n");
#endif
	// create device file at /dev
	misc_register(&miscdev);

	// enable device and map mmio
	r = pci_enable_device(dev);
	if (r < 0) {
#ifdef DEBUG
		dev_err(&(dev->dev), "pci_enable_device\n");
#endif
		goto error;
	}
	r = pci_request_region(dev, SS_PCI_BAR_MMIO, "ss-mmio");
	if (r != 0) {
#ifdef DEBUG
		dev_err(&(dev->dev), "pci_request_region\n");
#endif
		goto error;
	}

	ss_mmio = pci_iomap(dev, SS_PCI_BAR_MMIO, pci_resource_len(dev, SS_PCI_BAR_MMIO));
	if (ss_mmio == NULL) {
#ifdef DEBUG
		dev_err(&(dev->dev), "pci_iomap");
#endif
		goto error;
	}
	ss_pdev = dev;

	// dma
	pci_set_master(dev);    // important ! must do this to enable dma

	// msi irq
	// https://www.kernel.org/doc/html/latest/PCI/msi-howto.html
	r = pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI);
	if (r < 0) {
#ifdef DEBUG
		dev_err(&(dev->dev), "pci_alloc_irq_vectors\n");
#endif
		goto error;	
	}

	r = request_irq(pci_irq_vector(dev, 0), irq_handler_0, 0, DEVICE_NAME, NULL);
	if (r != 0) {
#ifdef DEBUG
		dev_err(&(dev->dev), "request_irq\n");
#endif
		goto error;
	}

#ifdef DEBUG
	printk(KERN_INFO "ss device magic: %llx\n", readq(ss_mmio + SS_MMIO_OFFSET_MAGIC));
#endif

	// now initialize finished, set device status to normal
	writeq(SS_CMD_TO_NORMAL, ss_mmio + SS_MMIO_OFFSET_COMMAND);
	device_is_idle = true;
	device_irq_occured = false;

// test
//static char buf[4096] = {0};
//readwriteblock(256, buf, 0);

	return 0;

error:
	return 1;
}

static void pci_remove(struct pci_dev *dev) {
	ss_pdev = NULL;
	ss_mmio = NULL;
	free_irq(pci_irq_vector(dev, 0), NULL);
	pci_free_irq_vectors(dev);
	pci_disable_device(dev);
	pci_release_region(dev, SS_PCI_BAR_MMIO);
	misc_deregister(&miscdev);
}


static struct pci_device_id pci_ids[] = {
	{ PCI_DEVICE(QEMU_VENDOR_ID, SS_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pci_ids);

static struct pci_driver pci_drv = {
	.name = DEVICE_NAME,    // this cannot be omitted !
	.id_table = pci_ids,
	.probe    = pci_probe,
	.remove   = pci_remove,
};


#endif

static int __init init_ss_module(void) {
	// major_version = register_chrdev(0, DEVICE_NAME, &fops);
	unsigned int i;
	
	for (i = 0; i < STORAGE_SLOT_COUNT; i++) {
		mutex_init(&storage_slot_lock[i]);

	}
#if SIMULATION
	zerostorage();
	misc_register(&miscdev);
#else
	if (pci_register_driver(&pci_drv) < 0) {
#ifdef DEBUG
		printk(KERN_ERR "pci_register_driver error\n");
#endif
		return 1;
	}
#endif

#ifdef DEBUG
	printk(KERN_ALERT "secure storage module init\n");
#endif
	return 0;
}

static void __exit exit_ss_module(void) {
#if SIMULATION
	// unregister_chrdev(major_version, DEVICE_NAME);
	misc_deregister(&miscdev);
#else
	pci_unregister_driver(&pci_drv);
#endif

#ifdef DEBUG
	printk(KERN_ALERT "secure storage module exit\n");
#endif
}


module_init(init_ss_module);
module_exit(exit_ss_module);

