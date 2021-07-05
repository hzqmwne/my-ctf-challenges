#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/module.h"


//#define DEBUG 1


#define TYPE_PCI_SS_DEVICE "ss"
#define SS(obj)        OBJECT_CHECK(SSState, obj, TYPE_PCI_SS_DEVICE)

#define SS_DEVICE_ID 0x7373

//#define DMA_START       0x40000
//#define DMA_SIZE        4096

#define SS_DEVICE_BLOCK_COUNT 256
#define SS_DEVICE_BLOCK_SIZE 4096

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
#define SS_SUBCMD_START_DMA_TO_DEVICE 0x10
#define SS_SUBCMD_START_DMA_FROM_DEVICE 0x20

typedef struct BackendStorageType_ BackendStorageType;
struct BackendStorageType_ {
	__attribute__((aligned(SS_DEVICE_BLOCK_SIZE))) unsigned char blocks[SS_DEVICE_BLOCK_COUNT][SS_DEVICE_BLOCK_SIZE];
	void (*reset_func)(BackendStorageType *bs);
	void (*read_func)(BackendStorageType *bs, unsigned int blocknum, void *buf);
	void (*write_func)(BackendStorageType *bs, unsigned int blocknum, const void *buf);
};

typedef struct {
	PCIDevice pdev;
	MemoryRegion mmio;

	QemuMutex status_mutex;
	uint64_t status;

	struct dma_state {
		uint64_t subcmd;
		uint64_t blocknum;
		dma_addr_t paddr;
	} dma;
	QEMUTimer dma_timer;

	BackendStorageType storage;
} SSState;

// -------------------------------------

#define FEISTEL_K 16
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void storage_internal_encrypt(void *dst, const void *src, unsigned int len) {
	unsigned int i;
	unsigned int j;
	unsigned long long left;
	unsigned long long right;
	unsigned long long oldright;
	for (i = 0; i < len / 16; i++) {
		memcpy(&left, ((const unsigned char *)src)+16*i, 8);    // memory may be unaligned
		memcpy(&right, ((const unsigned char *)src)+16*i+8, 8);
		for (j = 0; j < FEISTEL_K; j++) {    // feistel
			oldright = right;
			right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
			left = oldright;
		}
		memcpy(((unsigned char *)dst)+16*i, &right, 8);
		memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
	}
}

static void storage_internal_decrypt(void *dst, const void *src, unsigned int len) {
	unsigned int i;
	unsigned int j;
	unsigned long long left;
	unsigned long long right;
	unsigned long long oldright;
	for (i = 0; i < len / 16; i++) {
		memcpy(&left, ((const unsigned char *)src)+16*i, 8);    // memory may be unaligned
		memcpy(&right, ((const unsigned char *)src)+16*i+8, 8);
		for (j = 0; j < FEISTEL_K; j++) {    // feistel
			oldright = right;
			right = left ^ ROL64(right ^ 0x73706f3073706f30, 7);
			left = oldright;
		}
		memcpy(((unsigned char *)dst)+16*i, &right, 8);
		memcpy(((unsigned char *)dst)+16*i+8, &left, 8);
	}
}


static void storage_reset(BackendStorageType *storage) {
	unsigned long i;
	__attribute__((aligned(SS_DEVICE_BLOCK_SIZE))) static unsigned char zeroblock[SS_DEVICE_BLOCK_SIZE] = {0};
	for (i = 0; i < SS_DEVICE_BLOCK_COUNT; i++) {
		storage_internal_encrypt(&storage->blocks[i], zeroblock, SS_DEVICE_BLOCK_SIZE);
	}
}

static void storage_read(BackendStorageType *storage, unsigned int blocknum, void *buf) {
	storage_internal_decrypt(buf, &storage->blocks[blocknum], SS_DEVICE_BLOCK_SIZE);
}

static void storage_write(BackendStorageType *storage, unsigned int blocknum, const void *buf) {
	storage_internal_encrypt(&storage->blocks[blocknum], buf, SS_DEVICE_BLOCK_SIZE);
}

// -------------------------------------

static void ss_dma_timer(void *opaque) {
	SSState *ss = (SSState *)opaque;
	unsigned char buf[SS_DEVICE_BLOCK_SIZE] = {0};
	BackendStorageType *storage = &ss->storage;
	uint64_t subcmd = ss->dma.subcmd;    // prevent TOCTTOU
	uint64_t blocknum = ss->dma.blocknum;
	uint64_t paddr = ss->dma.paddr;
	uint64_t new_status;

#ifdef DEBUG
	printf("ss_dma_timer start, subcmd: %lx, blocknum: %lx, paddr: %lx\n", subcmd, blocknum, paddr);
#endif
	// do check
	if (!(subcmd == SS_SUBCMD_START_DMA_TO_DEVICE || subcmd == SS_SUBCMD_START_DMA_FROM_DEVICE)
			|| !(blocknum <= SS_DEVICE_BLOCK_COUNT)) {    // XXX: vuln! here should be "<", should not be "<="
		new_status = SS_STATUS_DMA_COMPLETE | SS_SUBSTATUS_DMA_COMPLETE_ERROR;
		// error
		goto finish;
	}

	// do dma
	if (subcmd == SS_SUBCMD_START_DMA_TO_DEVICE) {    // device get data from memory
		pci_dma_read(PCI_DEVICE(ss), paddr, buf, SS_DEVICE_BLOCK_SIZE);    // only allow read/write one block once
#ifdef DEBUG
		printf("ss_dma_timer SS_SUBCMD_START_DMA_TO_DEVICE, buf: %lx %lx %lx %lx\n", *(uint64_t *)buf, *(uint64_t *)(buf+8), *(uint64_t *)(buf+16), *(uint64_t *)(buf+24));
#endif
		storage->write_func(storage, blocknum, buf);
	}
	else if(subcmd == SS_SUBCMD_START_DMA_FROM_DEVICE) {    // device store data into memory
		storage->read_func(storage, blocknum, buf);
#ifdef DEBUG
		printf("ss_dma_timer SS_SUBCMD_START_DMA_FROM_DEVICE, buf: %lx %lx %lx %lx\n", *(uint64_t *)buf, *(uint64_t *)(buf+8), *(uint64_t *)(buf+16), *(uint64_t *)(buf+24));
#endif
		pci_dma_write(PCI_DEVICE(ss), paddr, buf, SS_DEVICE_BLOCK_SIZE);
		//cpu_physical_memory_write(paddr, buf, SS_DEVICE_BLOCK_SIZE);
	}
	new_status = SS_STATUS_DMA_COMPLETE | SS_SUBSTATUS_DMA_COMPLETE_SUCCESS;

finish:
	// raise irq and update status
	qemu_mutex_lock(&ss->status_mutex);    // to protect status change
	ss->status = new_status;
	qemu_mutex_unlock(&ss->status_mutex);
	msi_notify(PCI_DEVICE(ss), 0);    // still raise irq, even error occurs
}

static void ss_handle_cmd(SSState *ss, uint64_t cmd) {
	
	qemu_mutex_lock(&ss->status_mutex);    // to protect status change

#ifdef DEBUG
	printf("ss_handle_cmd cmd: %lx\n", cmd);
#endif

	uint64_t main_status = ss->status & SS_STATUS_MASK;
	uint64_t main_cmd = cmd & SS_CMD_MASK;
	uint64_t sub_cmd = cmd & SS_SUBCMD_MASK;

#ifdef DEBUG
	printf("ss_handle_cmd main_status: %lx, main_cmd: %lx, sub_cmd: %lx\n", main_status, main_cmd, sub_cmd);
#endif

	switch (main_cmd) {
		case SS_CMD_TO_NORMAL:
			if (main_status == SS_STATUS_BUSY) {
				break;
			}
			ss->status = SS_STATUS_NORMAL;
			break;
		case SS_CMD_PREPARE_DMA:
#ifdef DEBUG
			printf("ss_handle_cmd SS_CMD_PREPARE_DMA status: %lx\n", main_status);
#endif
			if (main_status != SS_STATUS_NORMAL) {
				break;
			}
			ss->status = SS_STATUS_DMA_PREPARE;
#ifdef DEBUG
			printf("ss_handle_cmd SS_CMD_PREPARE_DMA new status: %lx\n", ss->status);
#endif
			break;
		case SS_CMD_START_DMA:
			if (main_status != SS_STATUS_DMA_PREPARE) {
				break;
			}
			ss->status = SS_STATUS_BUSY;
			ss->dma.subcmd = sub_cmd;
#ifdef DEBUG
			printf("ss_handle_cmd SS_CMD_START_DMA\n");
#endif
			timer_mod(&ss->dma_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 5);
			break;
	}
	
	qemu_mutex_unlock(&ss->status_mutex);
}

static void ss_handle_write_dma_state(SSState *ss, hwaddr addr, uint64_t val) {
	qemu_mutex_lock(&ss->status_mutex);
	if (ss->status == SS_STATUS_DMA_PREPARE) {
		switch (addr) {
			case SS_MMIO_OFFSET_DMA_BLOCKNUM:    // dma block number
				ss->dma.blocknum = val;
				break;
			case SS_MMIO_OFFSET_DMA_PHYADDR:    // dma physical address
				ss->dma.paddr = val;
				break;
		}
	}
	qemu_mutex_unlock(&ss->status_mutex);
}

// -------------------------------------

static uint64_t ss_mmio_read(void *opaque, hwaddr addr, unsigned int size) {
	SSState *ss = (SSState *)opaque;
	uint64_t val = ~0ULL;

	if (size != 8) {
		return val;
	}

	switch (addr) {
		case SS_MMIO_OFFSET_MAGIC:    // magic const
			val = 0x3132303246544330;
			break;
		case SS_MMIO_OFFSET_STATUS:    // device status
			val = ss->status;
			break;
		case SS_MMIO_OFFSET_DMA_BLOCKNUM:    // dma block number
			val = ss->dma.blocknum;
			break;
		case SS_MMIO_OFFSET_DMA_PHYADDR:    // dma physical address
			val = ss->dma.paddr;
			break;
	}

	return val;
}

static void ss_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned int size) {
	SSState *ss = (SSState *)opaque;

	if (size != 8) {
		return;
	}

	switch (addr) {
		case SS_MMIO_OFFSET_COMMAND:    // command
			ss_handle_cmd(ss, val);
			break;
		case SS_MMIO_OFFSET_DMA_BLOCKNUM:    // dma block number
		case SS_MMIO_OFFSET_DMA_PHYADDR:    // dma physical address
			ss_handle_write_dma_state(ss, addr, val);
			break;
#ifdef DEBUG
		default:
			printf("Error: ss_mmio_write: addr %lx, val %lx\n", addr, val);
			break;
#endif
	}
}

static const MemoryRegionOps ss_mmio_ops = {
	.read = ss_mmio_read,
	.write = ss_mmio_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
		.valid = {
		.min_access_size = 4,
		.max_access_size = 8,
	},
	.impl = {
		.min_access_size = 4,
		.max_access_size = 8,
	},
};

// -------------------------------------

static void pci_ss_realize(PCIDevice *pdev, Error **errp) {
	SSState *ss = SS(pdev);
	uint8_t *pci_conf = pdev->config;
	BackendStorageType *storage = &ss->storage;

	storage->reset_func(storage);

	pci_config_set_interrupt_pin(pci_conf, 1);
	if (msi_init(pdev, 0, 1, true, false, errp)) {
		return;
	}

	qemu_mutex_init(&ss->status_mutex);
	timer_init_ms(&ss->dma_timer, QEMU_CLOCK_VIRTUAL, ss_dma_timer, ss);

	memory_region_init_io(&ss->mmio, OBJECT(ss), &ss_mmio_ops, ss, "ss-mmio", 1 * MiB);
	pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ss->mmio);

}

static void pci_ss_uninit(PCIDevice *pdev) {
	SSState *ss = SS(pdev);
	timer_del(&ss->dma_timer);
	qemu_mutex_destroy(&ss->status_mutex);
	msi_uninit(pdev);
}

// -------------------------------------

static void ss_instance_init(Object *obj) {
	SSState *ss = SS(obj);

	BackendStorageType *storage = &ss->storage;
	storage->reset_func = storage_reset;
	storage->read_func = storage_read;
	storage->write_func = storage_write;
}

static void ss_class_init(ObjectClass *class, void *data) {
	DeviceClass *dc = DEVICE_CLASS(class);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(class);
	k->realize = pci_ss_realize;
	k->exit = pci_ss_uninit;
	k->vendor_id = PCI_VENDOR_ID_QEMU;
	k->device_id = SS_DEVICE_ID;
	k->revision = 0x73;
	k->class_id = PCI_CLASS_OTHERS;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

// -------------------------------------

static void pci_ss_register_types(void) {
	static InterfaceInfo interfaces[] = {
		{ INTERFACE_CONVENTIONAL_PCI_DEVICE },
		{ },
	};

	static const TypeInfo ss_info = {
		.name = TYPE_PCI_SS_DEVICE,
		.parent = TYPE_PCI_DEVICE,
		.instance_size = sizeof(SSState),
		.instance_init = ss_instance_init,
		.class_init = ss_class_init,
		.interfaces = interfaces,
	};

	type_register_static(&ss_info);
}

type_init(pci_ss_register_types)

