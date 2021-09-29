package=crate_ppv-lite86_z
$(package)_crate_name=ppv-lite86
$(package)_version=0.2.10
$(package)_download_path=https://static.crates.io/crates/$($(package)_crate_name)
$(package)_file_name=$($(package)_crate_name)-$($(package)_version).crate
$(package)_sha256_hash=ac74c624d6b2d21f425f752262f42188365d7b8ff1aff74c82e45136510a4857
$(package)_crate_versioned_name=$($(package)_crate_name)

define $(package)_preprocess_cmds
  $(call generate_crate_checksum,$(package))
endef

define $(package)_stage_cmds
  $(call vendor_crate_source,$(package))
endef
