#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define KVMIO 0xAE

struct kvm_cca_vmi_cmd {
    uint8_t  cmd;
    uint8_t  size;
    uint16_t vcpu;
    uint32_t reg_id;
    uint64_t addr;
    uint64_t pid;
    uint64_t access_flags;
    uint64_t reserved[2];
    int32_t  status;
    uint32_t result_size;
    uint64_t result_val;
    uint8_t  result_buf[4096];
};

#define KVM_ARM_CCA_VMI_VM _IOWR(KVMIO, 0xd9, struct kvm_cca_vmi_cmd)

int main(int argc, char **argv)
{
    unsigned cmd = 3;
    uint64_t arg = 1;
    if (argc > 1) cmd = (unsigned)strtoul(argv[1], NULL, 0);
    if (argc > 2) arg = (uint64_t)strtoull(argv[2], NULL, 0);

    int fd = open("/dev/kvm", O_RDWR);
    if (fd < 0) { fprintf(stderr, "open /dev/kvm: %s\n", strerror(errno)); return 1; }

    struct kvm_cca_vmi_cmd c;
    memset(&c, 0, sizeof(c));
    c.cmd    = (uint8_t)cmd;
    c.reg_id = (uint32_t)arg;
    c.addr   = (uint64_t)arg;

    printf("[A1] sending cmd=%u arg=%llu via KVM_ARM_CCA_VMI_VM ...\n",
           cmd, (unsigned long long)arg);
    int r = ioctl(fd, KVM_ARM_CCA_VMI_VM, &c);
    if (r < 0)
        fprintf(stderr, "[A1] ioctl ret=%d errno=%d (%s) status=%d\n",
                r, errno, strerror(errno), c.status);
    else
        printf("[A1] ioctl ret=%d status=%d result_val=0x%016llx result_size=%u\n",
               r, c.status, (unsigned long long)c.result_val, c.result_size);

    close(fd);
    return r < 0 ? 1 : 0;
}
