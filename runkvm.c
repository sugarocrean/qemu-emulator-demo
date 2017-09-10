#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>


//#define DIRECT_MAP_BIN
#define GUEST_BIN_LOAD_ADDR  0x1000



#define KVM_DEVICE "/dev/kvm"
#define RAM_SIZE   0x1000
//#define CODE_START 0x1000
#define CODE_START 0
#define BINARY_FILE "guest.bin"

struct kvm {
   int dev_fd;	
   int vm_fd;
   __u64 ram_size;
   void *ram_start;
   int kvm_version;
   struct kvm_userspace_memory_region mem;

   struct vcpu *vcpu;
};

struct vcpu {
    int vcpu_fd;
    pthread_t vcpu_thread;
    struct kvm_run *kvm_run;
    int kvm_vcpu_mszie;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
};

static void
kvm_reset_vcpu (struct vcpu *vcpu)
{
    if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs)) < 0) {
        perror("can not get sregs\n");
        exit(1);
    }

    vcpu->sregs.cs.selector = CODE_START;
    vcpu->sregs.cs.base = CODE_START << 4;
#if 1
    vcpu->sregs.ss.selector = CODE_START;
    vcpu->sregs.ss.base = CODE_START * 16;
    vcpu->sregs.ds.selector = CODE_START;
    vcpu->sregs.ds.base = CODE_START *16;
    vcpu->sregs.es.selector = CODE_START;
    vcpu->sregs.es.base = CODE_START * 16;
    vcpu->sregs.fs.selector = CODE_START;
    vcpu->sregs.fs.base = CODE_START * 16;
    vcpu->sregs.gs.selector = CODE_START;
#endif

    if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0) {
        perror("can not set sregs");
        exit(1);
    }

    vcpu->regs.rflags = 0x0000000000000002ULL;
    vcpu->regs.rip = GUEST_BIN_LOAD_ADDR;
    vcpu->regs.rsp = 0xffffffff;
    vcpu->regs.rbp = 0;

    if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs)) < 0) {
        perror("KVM SET REGS\n");
        exit(1);
    }
}

static void *kvm_run_vm(void *data)
{
    struct kvm *kvm = (struct kvm *)data;
    int ret = 0;
    static char mmio[8];
    kvm_reset_vcpu(kvm->vcpu);

    while (1) {
        printf("KVM start run\n");
        ret = ioctl(kvm->vcpu->vcpu_fd, KVM_RUN, 0);
	
        if (ret < 0) {
            fprintf(stderr, "KVM_RUN failed\n");
            exit(1);
        }

        switch (kvm->vcpu->kvm_run->exit_reason) {
        case KVM_EXIT_UNKNOWN:
            printf("KVM_EXIT_UNKNOWN\n");
            break;

        case KVM_EXIT_DEBUG:
            printf("KVM_EXIT_DEBUG\n");
            break;

        case KVM_EXIT_IO:
            printf("KVM_EXIT_IO\n");
            printf("out port: %d, data: %x\n", 
                   kvm->vcpu->kvm_run->io.port,  
                   *(int *)((char *)(kvm->vcpu->kvm_run) + kvm->vcpu->kvm_run->io.data_offset)
                   );
            break;

        case KVM_EXIT_MMIO:
            printf("KVM_EXIT_MMIO\n");
            if (kvm->vcpu->kvm_run->mmio.is_write) {
                printf("Write %d bytes to address %x\n", 
                       kvm->vcpu->kvm_run->mmio.len,
                       kvm->vcpu->kvm_run->mmio.phys_addr);
                memcpy(mmio, kvm->vcpu->kvm_run->mmio.data, 
                       kvm->vcpu->kvm_run->mmio.len);
            } else {
                printf("Read %d bytes from address %x\n", 
                       kvm->vcpu->kvm_run->mmio.len,
                       kvm->vcpu->kvm_run->mmio.phys_addr);
                memcpy(kvm->vcpu->kvm_run->mmio.data, mmio, 
                       kvm->vcpu->kvm_run->mmio.len);
            }
            break;

        case KVM_EXIT_INTR:
            printf("KVM_EXIT_INTR\n");
            break;

	case KVM_EXIT_SHUTDOWN:
	    printf("KVM_EXIT_SHUTDOWN\n");
	    goto exit_kvm;
	    break;

	default:
	    printf("KVM PANIC\n");
	    goto exit_kvm;
	}
    }

exit_kvm:
    return 0;
}

static void load_guest_bin(struct kvm *kvm)
{
    struct stat sb;
    int rsize;
    int ret;
    int fd;

    fd = open(BINARY_FILE, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "can not open binary file\n");
        exit(1);
    }

    if (fstat(fd, &sb) == -1) {
        fprintf(stderr, "fstat()\n");
        exit(-1);
    }

    if (sb.st_size > kvm->ram_size) {
        fprintf(stderr, "xxxxx\n");
        exit(-1);
    }

    rsize = sb.st_size;

    char *p = kvm->ram_start;

    while(1) {
        ret = read(fd, p, rsize);
        if (ret <= 0) {
            break;
        }
        printf("read guest binary size: %d\n", ret);
        p += ret;
        rsize -= ret;
    }
}

static struct kvm *kvm_init(void)
{
    struct kvm *kvm = malloc(sizeof(struct kvm));
    kvm->dev_fd = open(KVM_DEVICE, O_RDWR);

    if (kvm->dev_fd < 0) {
        perror("open kvm device fault: ");
        return NULL;
    }

    kvm->kvm_version = ioctl(kvm->dev_fd, KVM_GET_API_VERSION, 0);

    return kvm;
}

static void kvm_clean(struct kvm *kvm)
{
    assert (kvm != NULL);
    close(kvm->dev_fd);
    free(kvm);
}

static int kvm_create_vm(struct kvm *kvm, int ram_size)
{
    int ret = 0;
    kvm->vm_fd = ioctl(kvm->dev_fd, KVM_CREATE_VM, 0);

    if (kvm->vm_fd < 0) {
        perror("can not create vm");
        return -1;
    }
#ifdef DIRECT_MAP_BIN
    printf("map guest binary directly\n");
    struct stat sb;
    int fd = open(BINARY_FILE, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "can not open binary file\n");
        exit(1);
    } 

    if (fstat(fd, &sb) == -1) {
        fprintf(stderr, "fstat()\n");
        exit(-1);
    }

    kvm->ram_size = ram_size > sb.st_size ? ram_size : sb.st_size;
    if (kvm->ram_size != ram_size) {
        fprintf(stderr, "ram size is ajusted from %x to %x\n",
                ram_size, kvm->ram_size);
    }

    kvm->ram_start = mmap(NULL, kvm->ram_size, 
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE, 
                          fd, 0);
    (void)close(fd);
#else
    kvm->ram_size = ram_size;
    kvm->ram_start = mmap(NULL, kvm->ram_size, 
                          PROT_READ | PROT_WRITE, 
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 
			  -1, 0);
#endif
    if (kvm->ram_start == MAP_FAILED) {
        perror("can not mmap ram");
        return -1;
    }

    kvm->mem.slot = 0;
    kvm->mem.guest_phys_addr = GUEST_BIN_LOAD_ADDR;
    kvm->mem.memory_size = kvm->ram_size;
    kvm->mem.userspace_addr = (__u64)kvm->ram_start;

    ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(kvm->mem));

    if (ret < 0) {
        perror("can not set user memory region");
        return ret;
    }

    return ret;
}

static void
kvm_clean_vm(struct kvm *kvm) 
{
    close(kvm->vm_fd);
    munmap(kvm->ram_start, kvm->ram_size);
}

static struct vcpu *
kvm_init_vcpu(struct kvm *kvm)
{
    struct vcpu *vcpu = malloc(sizeof(struct vcpu));

    /*
     * create a vcpu with vcpuid is 0
     */
    vcpu->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu->vcpu_fd < 0) {
        perror("can not create vcpu");
        return NULL;
    }

    vcpu->kvm_vcpu_mszie = ioctl(kvm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpu->kvm_vcpu_mszie < 0) {
        perror("can not get vcpu mmsize");
        return NULL;
    }

    printf("vcpu mmap size: %x\n", vcpu->kvm_vcpu_mszie);
    vcpu->kvm_run = mmap(NULL, vcpu->kvm_vcpu_mszie, 
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED,
                         vcpu->vcpu_fd, 0);

    if (vcpu->kvm_run == MAP_FAILED) {
        perror("can not mmap kvm_run");
        return NULL;
    }

    return vcpu;
}

static void 
kvm_clean_vcpu(struct vcpu *vcpu)
{
    munmap(vcpu->kvm_run, vcpu->kvm_vcpu_mszie);
    close(vcpu->vcpu_fd);
}

int main(int argc, char **argv)
{
    struct kvm *kvm;

    kvm = kvm_init();
    if (kvm == NULL) {
        fprintf(stderr, "kvm init\n");
        exit(-1);
    }

    if (kvm_create_vm(kvm, RAM_SIZE) < 0) {
        fprintf(stderr, "create vm fault\n");
        exit(-1);
    }

#ifdef DIRECT_MAP_BIN
    // null
#else
    load_guest_bin(kvm);
#endif

    kvm->vcpu = kvm_init_vcpu(kvm);

    kvm_run_vm(kvm);

    kvm_clean_vm(kvm);
    kvm_clean_vcpu(kvm->vcpu);
    kvm_clean(kvm);

    return 0;
}

