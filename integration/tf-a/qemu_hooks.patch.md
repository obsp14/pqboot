# Hooking pqboot into TF-A's QEMU platform (manual patch, UNTESTED)

TF-A changes between releases, so this is written as instructions rather
than a `git apply`-able patch. Function names below exist in TF-A v2.10+;
check them in your checkout with `git grep`.

## 1. BL2: verify BL31 / BL32 / BL33 after they are loaded

File: `plat/qemu/common/qemu_bl2_setup.c`

At the very top of `qemu_bl2_handle_post_image_load(unsigned int image_id)`
(called from `bl2_plat_handle_post_image_load`), before the existing
`switch (image_id)`:

```c
#include <common/desc_image_load.h>

void pqb_tfa_verify_loaded(unsigned int image_id, uintptr_t base, size_t size);

/* ... inside qemu_bl2_handle_post_image_load(): */
	bl_mem_params_node_t *pqb_p = get_bl_mem_params_node(image_id);
	assert(pqb_p != NULL);
	pqb_tfa_verify_loaded(image_id, pqb_p->image_info.image_base,
			      pqb_p->image_info.image_size);
```

`image_info.image_size` is the number of bytes TF-A actually read from the
FIP, i.e. payload + signature trailer.

## 2. BL1: start the DICE chain and verify BL2

File: `plat/qemu/common/qemu_bl1_setup.c` (or add the override there)

TF-A provides a weak `bl1_plat_handle_post_image_load()` in
`plat/common/plat_bl1_common.c`. It also fills in BL2's memory layout
argument, so do NOT simply replace it: copy its body into a QEMU-specific
override and add, at the start:

```c
void pqb_tfa_dice_begin(void);
void pqb_tfa_verify_loaded(unsigned int image_id, uintptr_t base, size_t size);

	if (image_id == BL2_IMAGE_ID) {
		image_desc_t *d = bl1_plat_get_image_desc(BL2_IMAGE_ID);
		pqb_tfa_dice_begin();
		pqb_tfa_verify_loaded(BL2_IMAGE_ID, d->image_info.image_base,
				      d->image_info.image_size);
	}
```

## 3. Platform makefile

File: `plat/qemu/qemu/platform.mk`, at the end:

```make
ifdef PQBOOT_DIR
include $(PQBOOT_DIR)/integration/tf-a/pqboot.mk
endif
```

## 4. Map the DICE hand-off page

Add to the BL1 and BL2 memory maps in `plat/qemu/common/qemu_common.c`
(`plat_qemu_mmap` / the `MAP_*` lists):

```c
#define MAP_PQB_HANDOFF MAP_REGION_FLAT(0x0efff000, 0x1000, \
				MT_MEMORY | MT_RW | MT_SECURE)
```

and shrink OP-TEE's secure DRAM by 4 KiB so nothing else uses that page
(`CFG_TZDRAM_SIZE=0x00eff000` when building OP-TEE).

## 5. Things that will probably need adjusting

* BL1/BL2 RW region size: the pqboot code + mbedTLS ECDSA adds tens of KiB.
  If the link fails with "region overflowed", raise `BL1_RW_SIZE` /
  `BL2_SIZE`-style limits in `plat/qemu/qemu/include/platform_def.h`.
* OP-TEE as BL32 on qemu_v8 is loaded as three images (header, pager,
  pageable: `BL32_EXTRA1/2`). Sign `tee-pager_v2.bin` as BL32 and either
  sign the extras with type `kernel`/`test` and add their IDs to
  `tfa_id_to_pqb_type()`, or build OP-TEE without paging
  (`CFG_WITH_PAGER=n`, single `tee-raw.bin`).
* `mbedtls_init()` must not be called twice if TRUSTED_BOARD_BOOT is also
  enabled; guard it if you combine both.
