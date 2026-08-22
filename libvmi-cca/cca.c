#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <glib.h>

#include "private.h"
#include "driver/driver_interface.h"
#include "driver/memory_cache.h"
#include "driver/cca/cca_private.h"

/* ----------------------------------------------------------------
 *  Helper: send a VMI command to KVM via ioctl
 * ---------------------------------------------------------------- */
static status_t
cca_send_cmd(cca_instance_t *cca, struct cca_vmi_cmd *cmd)
{
    if (cca->vm_fd < 0) {
        errprint("CCA: vm_fd not open\n");
        return VMI_FAILURE;
    }

    if (ioctl(cca->vm_fd, KVM_ARM_CCA_VMI_VM, cmd) < 0) {
        errprint("CCA: ioctl KVM_ARM_CCA_VMI_VM failed\n");
        return VMI_FAILURE;
    }

    if (cmd->status != 0) {
        dbprint(VMI_DEBUG_DRIVER, "CCA: cmd %d returned status %d\n",
                cmd->cmd, cmd->status);
        return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

/* ----------------------------------------------------------------
 *  Helper: find debugfs path for a Realm VM
 * ---------------------------------------------------------------- */
static int
cca_find_realm_debugfs(const char *name, char *path, size_t pathlen)
{
    DIR *dir;
    struct dirent *entry;
    char probe[512];
    FILE *fp;
    char buf[256];

    dir = opendir("/sys/kernel/debug/kvm");
    if (!dir)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        snprintf(probe, sizeof(probe),
                 "/sys/kernel/debug/kvm/%s/vmi_scan", entry->d_name);

        if (access(probe, F_OK) == 0) {
            snprintf(path, pathlen,
                     "/sys/kernel/debug/kvm/%s/vmi_scan", entry->d_name);
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}

/* ----------------------------------------------------------------
 *  Probe: can we talk to a CCA Realm?
 * ---------------------------------------------------------------- */
status_t
cca_test(uint64_t domainid, const char *name,
         uint64_t init_flags, vmi_init_data_t *init_data)
{
    char path[256];

    /* Check if there is a KVM Realm with vmi_scan debugfs node */
    if (cca_find_realm_debugfs(name, path, sizeof(path)) == 0) {
        dbprint(VMI_DEBUG_DRIVER, "CCA: found Realm debugfs at %s\n", path);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

/* ----------------------------------------------------------------
 *  Lifecycle: init
 * ---------------------------------------------------------------- */
status_t
cca_init(vmi_instance_t vmi, uint32_t init_flags,
         vmi_init_data_t *init_data)
{
    cca_instance_t *cca = g_malloc0(sizeof(cca_instance_t));
    if (!cca)
        return VMI_FAILURE;

    cca->vm_fd = -1;
    cca->paused = false;

    /* Try to find the debugfs path */
    cca_find_realm_debugfs(NULL, cca->debugfs_path, sizeof(cca->debugfs_path));

    /* Try to open the VM fd from init_data if provided */
    if (init_data) {
        for (unsigned int i = 0; i < init_data->count; i++) {
            if (init_data->entry[i].type == VMI_INIT_DATA_KVMI_SOCKET) {
                /* Reuse this entry type for CCA vm_fd path */
                int fd = open((const char *)init_data->entry[i].data, O_RDWR);
                if (fd >= 0)
                    cca->vm_fd = fd;
            }
        }
    }

    vmi->driver.driver_data = (void *)cca;

    return VMI_SUCCESS;
}

status_t
cca_init_vmi(vmi_instance_t vmi, uint32_t init_flags,
             vmi_init_data_t *init_data)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    /* Set arch to ARM64 */
    vmi->page_mode = VMI_PM_AARCH64;

    /* Query memory size from kernel if vm_fd is available */
    if (cca->vm_fd >= 0) {
        struct cca_vmi_cmd cmd = { 0 };
        cmd.cmd = CCA_VMI_CMD_GET_VCPUREGS;  /* piggyback memsize query */
        /* For now, use hardcoded values matching FVP Realm config */
    }

    /* Default values matching typical FVP Realm configuration */
    if (cca->allocated_ram_size == 0)
        cca->allocated_ram_size = 512 * 1024 * 1024ULL;  /* 512MB */
    if (cca->max_physical_address == 0)
        cca->max_physical_address = cca->allocated_ram_size;
    if (cca->num_vcpus == 0)
        cca->num_vcpus = 1;

    return VMI_SUCCESS;
}

/* ----------------------------------------------------------------
 *  Lifecycle: destroy
 * ---------------------------------------------------------------- */
void
cca_destroy(vmi_instance_t vmi)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return;

    if (cca->vm_fd >= 0)
        close(cca->vm_fd);

    g_free(cca->name);
    g_free(cca);

    vmi->driver.driver_data = NULL;
}

/* ----------------------------------------------------------------
 *  Domain identification
 * ---------------------------------------------------------------- */
uint64_t
cca_get_id_from_name(vmi_instance_t vmi, const char *name)
{
    /* In CCA/FVP environment, we typically have a single Realm.
     * Return a fixed ID.  A production version would enumerate
     * /sys/kernel/debug/kvm/ entries. */
    return 1;
}

uint64_t
cca_get_id(vmi_instance_t vmi)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    return cca ? cca->domain_id : 0;
}

void
cca_set_id(vmi_instance_t vmi, uint64_t domainid)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (cca)
        cca->domain_id = domainid;
}

status_t
cca_check_id(vmi_instance_t vmi, uint64_t domainid)
{
    /* Accept any ID for now */
    return VMI_SUCCESS;
}

status_t
cca_get_name(vmi_instance_t vmi, char **name)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (cca && cca->name) {
        *name = g_strdup(cca->name);
        return VMI_SUCCESS;
    }
    return VMI_FAILURE;
}

void
cca_set_name(vmi_instance_t vmi, const char *name)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (cca) {
        g_free(cca->name);
        cca->name = g_strdup(name);
    }
}

/* ----------------------------------------------------------------
 *  Memory geometry
 * ---------------------------------------------------------------- */
status_t
cca_get_memsize(vmi_instance_t vmi,
                uint64_t *allocated_ram_size,
                addr_t *maximum_physical_address)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    *allocated_ram_size = cca->allocated_ram_size;
    *maximum_physical_address = cca->max_physical_address;
    return VMI_SUCCESS;
}

/* ----------------------------------------------------------------
 *  Memory read — the core VMI operation
 *
 *  Each call reads one 4KB page from the Realm via RMM.
 *  The ioctl sends a READ_PA command; RMM decrypts and
 *  returns the page content via rec_run.exit.
 * ---------------------------------------------------------------- */
static void *
cca_read_page_impl(vmi_instance_t vmi, addr_t page)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return NULL;

    void *buf = g_malloc0(vmi->page_size);
    if (!buf)
        return NULL;

    struct cca_vmi_cmd cmd = { 0 };
    cmd.cmd = CCA_VMI_CMD_READ_PA;
    cmd.addr = page << 12;
    cmd.size = vmi->page_size;

    if (cca_send_cmd(cca, &cmd) == VMI_SUCCESS && cmd.result_size > 0) {
        uint32_t copy_size = cmd.result_size;
        if (copy_size > vmi->page_size)
            copy_size = vmi->page_size;
        memcpy(buf, cmd.result_buf, copy_size);
        return buf;
    }

    /* Fallback: try debugfs trigger for legacy full-scan mode */
    if (cca->debugfs_path[0] != '\0') {
        FILE *fp = fopen(cca->debugfs_path, "w");
        if (fp) {
            fprintf(fp, "1");
            fclose(fp);
            dbprint(VMI_DEBUG_DRIVER,
                    "CCA: triggered legacy debugfs scan for page 0x%lx\n",
                    (unsigned long)page);
        }
    }

    g_free(buf);
    return NULL;
}

void *
cca_read_page(vmi_instance_t vmi, addr_t page)
{
    return cca_read_page_impl(vmi, page);
}

/* ----------------------------------------------------------------
 *  Memory write — limited in CCA (Realm memory is encrypted)
 * ---------------------------------------------------------------- */
status_t
cca_write(vmi_instance_t vmi, addr_t paddr,
          void *buf, uint32_t length)
{
    /* CCA Realm memory is hardware-encrypted.
     * Write from host is not supported by design. */
    errprint("CCA: write to Realm memory is not supported "
             "(memory is hardware-encrypted)\n");
    return VMI_FAILURE;
}

/* ----------------------------------------------------------------
 *  vCPU register access
 * ---------------------------------------------------------------- */
status_t
cca_get_vcpureg(vmi_instance_t vmi, uint64_t *value,
                reg_t reg, unsigned long vcpu)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    struct cca_vmi_cmd cmd = { 0 };
    cmd.cmd = CCA_VMI_CMD_GET_VCPUREG;
    cmd.vcpu = (uint16_t)vcpu;
    cmd.reg_id = (uint32_t)reg;

    if (cca_send_cmd(cca, &cmd) == VMI_SUCCESS) {
        *value = cmd.result_val;
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t
cca_get_vcpuregs(vmi_instance_t vmi, registers_t *regs,
                 unsigned long vcpu)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    struct cca_vmi_cmd cmd = { 0 };
    cmd.cmd = CCA_VMI_CMD_GET_VCPUREGS;
    cmd.vcpu = (uint16_t)vcpu;

    if (cca_send_cmd(cca, &cmd) == VMI_SUCCESS) {
        /* Copy register block from result_buf into regs.
         * The layout in result_buf must match what RMM writes
         * in rec_active_plane_sysregs(). */
        if (cmd.result_size >= sizeof(registers_t))
            memcpy(regs, cmd.result_buf, sizeof(registers_t));
        else if (cmd.result_size > 0)
            memcpy(regs, cmd.result_buf, cmd.result_size);
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

/* ----------------------------------------------------------------
 *  VM pause / resume
 * ---------------------------------------------------------------- */
status_t
cca_pause_vm(vmi_instance_t vmi)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    if (cca->paused)
        return VMI_SUCCESS;

    struct cca_vmi_cmd cmd = { 0 };
    cmd.cmd = CCA_VMI_CMD_PAUSE_VM;

    if (cca_send_cmd(cca, &cmd) == VMI_SUCCESS) {
        cca->paused = true;
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

status_t
cca_resume_vm(vmi_instance_t vmi)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    if (!cca->paused)
        return VMI_SUCCESS;

    struct cca_vmi_cmd cmd = { 0 };
    cmd.cmd = CCA_VMI_CMD_RESUME_VM;

    if (cca_send_cmd(cca, &cmd) == VMI_SUCCESS) {
        cca->paused = false;
        return VMI_SUCCESS;
    }

    return VMI_FAILURE;
}

/* ----------------------------------------------------------------
 *  Memory events (page traps — maps to RMM R3)
 * ---------------------------------------------------------------- */
status_t
cca_set_mem_access(vmi_instance_t vmi, addr_t gpfn,
                   vmi_mem_access_t page_access_flag,
                   uint16_t vmm_pagetable_id)
{
    cca_instance_t *cca = cca_get_instance(vmi);
    if (!cca)
        return VMI_FAILURE;

    struct cca_vmi_cmd cmd = { 0 };
    if (page_access_flag == VMI_MEMACCESS_N) {
        cmd.cmd = CCA_VMI_CMD_CLR_MEM_EVENT;
    } else {
        cmd.cmd = CCA_VMI_CMD_SET_MEM_EVENT;
    }
    cmd.addr = gpfn;
    cmd.access_flags = (uint64_t)page_access_flag;

    return cca_send_cmd(cca, &cmd);
}

/* ----------------------------------------------------------------
 *  Misc
 * ---------------------------------------------------------------- */
int
cca_is_pv(vmi_instance_t vmi)
{
    return 0;  /* Realm VMs are not paravirtualized */
}
