#ifndef CCA_H
#define CCA_H

status_t cca_test(
    uint64_t domainid,
    const char *name,
    uint64_t init_flags,
    vmi_init_data_t *init_data);

status_t cca_init(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

status_t cca_init_vmi(
    vmi_instance_t vmi,
    uint32_t init_flags,
    vmi_init_data_t *init_data);

void cca_destroy(
    vmi_instance_t vmi);

uint64_t cca_get_id_from_name(
    vmi_instance_t vmi,
    const char *name);

uint64_t cca_get_id(
    vmi_instance_t vmi);

void cca_set_id(
    vmi_instance_t vmi,
    uint64_t domainid);

status_t cca_check_id(
    vmi_instance_t vmi,
    uint64_t domainid);

status_t cca_get_name(
    vmi_instance_t vmi,
    char **name);

void cca_set_name(
    vmi_instance_t vmi,
    const char *name);

status_t cca_get_memsize(
    vmi_instance_t vmi,
    uint64_t *allocated_ram_size,
    addr_t *maximum_physical_address);

void *cca_read_page(
    vmi_instance_t vmi,
    addr_t page);

status_t cca_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length);

status_t cca_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu);

status_t cca_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu);

status_t cca_pause_vm(
    vmi_instance_t vmi);

status_t cca_resume_vm(
    vmi_instance_t vmi);

status_t cca_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id);

int cca_is_pv(
    vmi_instance_t vmi);

static inline status_t
driver_cca_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &cca_init;
    driver.init_vmi_ptr = &cca_init_vmi;
    driver.destroy_ptr = &cca_destroy;
    driver.get_id_from_name_ptr = &cca_get_id_from_name;
    driver.get_id_ptr = &cca_get_id;
    driver.set_id_ptr = &cca_set_id;
    driver.check_id_ptr = &cca_check_id;
    driver.get_name_ptr = &cca_get_name;
    driver.set_name_ptr = &cca_set_name;
    driver.get_memsize_ptr = &cca_get_memsize;
    driver.read_page_ptr = &cca_read_page;
    driver.write_ptr = &cca_write;
    driver.get_vcpureg_ptr = &cca_get_vcpureg;
    driver.get_vcpuregs_ptr = &cca_get_vcpuregs;
    driver.is_pv_ptr = &cca_is_pv;
    driver.pause_vm_ptr = &cca_pause_vm;
    driver.resume_vm_ptr = &cca_resume_vm;
    driver.set_mem_access_ptr = &cca_set_mem_access;
    vmi->driver = driver;
    return VMI_SUCCESS;
}

#endif /* CCA_H */
