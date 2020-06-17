package=libzendoo
$(package)_version=0.1.0
$(package)_download_path=https://github.com/ZencashOfficial/zendoo-mc-cryptolib/archive/
$(package)_file_name=$(package)-$($(package)_git_commit).tar.gz
$(package)_download_file=$($(package)_git_commit).tar.gz
$(package)_sha256_hash=f46dac88b1d704e91e4c18cf712202106e94b828fe024ea540dd6d43389a44e2
$(package)_git_commit=71ed4d26ded2f63cfebc3a57a78a6d86c98c30b5
$(package)_dependencies=rust $(rust_crates_zendoo)
$(package)_patches=cargo.config

ifeq ($(host_os),mingw32)
$(package)_library_file=target/x86_64-pc-windows-gnu/release/zendoo_mc.lib
else
$(package)_library_file=target/release/libzendoo_mc.a
endif

define $(package)_set_vars
$(package)_build_opts=  --release  --all-features
$(package)_build_opts_mingw32=--target=x86_64-pc-windows-gnu
endef

define $(package)_preprocess_cmds
  mkdir .cargo && \
  cat $($(package)_patch_dir)/cargo.config | sed 's|CRATE_REGISTRY|$(host_prefix)/$(CRATE_REGISTRY)|' > .cargo/config
endef

define $(package)_build_cmds
  cargo build $($(package)_build_opts)
endef


define $(package)_stage_cmds
  mkdir $($(package)_staging_dir)$(host_prefix)/lib/ && \
  mkdir $($(package)_staging_dir)$(host_prefix)/include/ && \
  mkdir $($(package)_staging_dir)$(host_prefix)/include/zendoo/ && \
  cp $($(package)_library_file) $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp include/zendoo_mc.h $($(package)_staging_dir)$(host_prefix)/include/zendoo && \
  cp include/error.h $($(package)_staging_dir)$(host_prefix)/include/zendoo
endef
