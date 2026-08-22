#ifndef CCA_PRIVATE_H
#define CCA_PRIVATE_H

#include <stdint.h>
#include <stdbool.h>

/* ioctl command number — must match host kernel's include/uapi/linux/kvm.h */
#define KVMIO 0xAE
#define KVM_ARM_CCA_VMI_VM  _IOWR(KVMIO, 0xd9, struct cca_vmi_cmd)

/* VMI command types (maps to rec_run.enter.flags bits[62:56]) */
#define CCA_VMI_CMD_FULL_SCAN     0
#define CCA_VMI_CMD_READ_PA       1
#define CCA_VMI_CMD_READ_VA       2
#define CCA_VMI_CMD_GET_VCPUREG   3
#define CCA_VMI_CMD_GET_VCPUREGS  4
#define CCA_VMI_CMD_PAUSE_VM      5
#define CCA_VMI_CMD_RESUME_VM     6
#define CCA_VMI_CMD_SET_MEM_EVENT 7
#define CCA_VMI_CMD_CLR_MEM_EVENT 8

/* ioctl request/response structure */
struct cca_vmi_cmd {
    /* request */
    uint8_t  cmd;
    uint8_t  size;
    uint16_t vcpu;
    uint32_t reg_id;
    uint64_t addr;
    uint64_t pid;
    uint64_t access_flags;
    uint64_t reserved[2];

    /* response (filled by kernel) */
    int32_t  status;
    uint32_t result_size;
    uint64_t result_val;
    uint8_t  result_buf[4096];
};

/* Per-instance data stored in vmi->driver.driver_data */
typedef struct cca_instance {
    int      vm_fd;
    char    *name;
    uint64_t domain_id;
    char     debugfs_path[256];
    uint64_t max_physical_address;
    uint64_t allocated_ram_size;
    unsigned int num_vcpus;
    bool     paused;
} cca_instance_t;

static inline cca_instance_t *
cca_get_instance(vmi_instance_t vmi)
{
    return (cca_instance_t *)vmi->driver.driver_data;
}

#endif /* CCA_PRIVATE_H */
