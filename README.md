# RealmEye Artifact

Source code accompanying the paper *RealmEye: Confidential VM Introspection
for Arm CCA under Hypervisor-Rootkit Collusion*.

The paper reports two prototypes that realise the same design on two
platforms. They are not a single binary: the FVP prototype builds on Arm's
CCA reference software stack and serves functionality and detection
evaluation (Sec. 7.1), whereas the OpenCCA prototype runs on a commercial
RK3588 board and serves performance and collusion evaluation (Sec. 7.2-7.4).
Both trees are included below.

## Layout

| Directory | Contents | Paper section |
|---|---|---|
| `rmm-opencca/` | RMM-side introspection for the RK3588 prototype, in the original TF-RMM directory layout | 5.2, 5.4 |
| `rmm-fvp/` | RMM-side introspection for the FVP prototype (all VMI logic resides in `run.c`) | 5.1, 7.1 |
| `host-kvm/` | Normal-world KVM glue that forwards control information and results (~354 lines) | 5.1 |
| `libvmi-cca/` | LibVMI CCA driver backend | 5.3 |
| `tests/` | Test programs used in the experiments | 7.4 |

## rmm-opencca/

Applies to TF-RMM v0.8.0 as adapted by OpenCCA. The introspection core is
`runtime/rmi/vmi.c` with its header `runtime/include/vmi.h`;
`runtime/core/exit.c` carries the Stage-2 write-trap hook,
`runtime/rmi/run.c` and `runtime/core/handler.c` the trigger and dispatch
path, `lib/smc/include/smc-rmi.h` the encrypted record layout, and
`configs/mbedtls/rmm_mbedtls_config.h` enables the AES-GCM modules of the
in-tree mbedTLS.

Build with `RMM_VMI=ON`. The resident introspection logic is about 417
lines; the build additionally compiles about 562 lines of benchmarking and
diagnostic code that do not belong to the mechanism and can be removed from
a production build (Sec. 5.4).

## rmm-fvp/

The FVP prototype predates the modularisation of the OpenCCA tree, so its
VMI logic is embedded in `runtime/rmi/run.c` rather than a separate file.
It shares the software Stage-1 walker, the memory-read primitive and the
Stage-2 write trap with the OpenCCA tree, and is the tree on which the
Diamorphine detection results of Sec. 7.1 were obtained.

## tests/

- `vic.c` - a controlled test process that flips its own `uid` through
  `setresuid` on `SIGUSR1`/`SIGUSR2`. It is a benign harness, not a rootkit;
  it isolates the single variable of the collusion experiment, namely
  whether scan timing is visible to the attacker (Sec. 7.4).
- `f3_target.c`, `Makefile` - a kernel module that writes to its own target
  page, used to demonstrate the write trap end to end (Sec. 7.4).
- `a1_test.c` - host-side command driver used to issue the introspection
  commands described in Sec. 5.2.

## Limitations

The prototype limitations stated in the paper apply to this code: the
Stage-1 walker is fixed to 48-bit virtual addresses with a 4 KB granule and
does not parse `TCR_EL1`; the write trap is one-shot and requires re-arming
after a hit; the result channel uses a preset symmetric key, so its
guarantees hold within a single boot session and the attestation-rooted key
derivation of Sec. 4.5 is not yet implemented.
