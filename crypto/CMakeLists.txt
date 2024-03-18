# TODO(crbug.com/boringssl/524): Avoid needing this transform by instead moving
# this up a directory.
list(TRANSFORM BCM_SOURCES_ASM PREPEND "../")
list(TRANSFORM BCM_SOURCES_NASM PREPEND "../")
list(TRANSFORM CRYPTO_SOURCES_ASM PREPEND "../")
list(TRANSFORM CRYPTO_SOURCES_NASM PREPEND "../")

if(OPENSSL_ASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_ASM})
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_ASM})
endif()
if(OPENSSL_NASM)
  list(APPEND CRYPTO_SOURCES_ASM_USED ${CRYPTO_SOURCES_NASM})
  list(APPEND BCM_SOURCES_ASM_USED ${BCM_SOURCES_NASM})
endif()

if(FIPS_DELOCATE AND FIPS_SHARED)
  message(FATAL_ERROR "Can't set both delocate and shared mode for FIPS build")
endif()

if(FIPS_DELOCATE)
  add_library(bcm_c_generated_asm STATIC fipsmodule/bcm.c)
  add_dependencies(bcm_c_generated_asm boringssl_prefix_symbols)
  target_include_directories(bcm_c_generated_asm PRIVATE ${PROJECT_SOURCE_DIR}/include)
  set_target_properties(bcm_c_generated_asm PROPERTIES COMPILE_OPTIONS "-S")
  set_target_properties(bcm_c_generated_asm PROPERTIES POSITION_INDEPENDENT_CODE ON)

  set(TARGET_FLAG "")
  if(CMAKE_ASM_COMPILER_TARGET)
    set(TARGET_FLAG "--target=${CMAKE_ASM_COMPILER_TARGET}")
  endif()

  go_executable(delocate boringssl.googlesource.com/boringssl/util/fipstools/delocate)
  add_custom_command(
    OUTPUT bcm-delocated.S
    COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/delocate
    -a $<TARGET_FILE:bcm_c_generated_asm>
    -o ${CMAKE_CURRENT_BINARY_DIR}/bcm-delocated.S
    -cc ${CMAKE_ASM_COMPILER}
    -cc-flags "${TARGET_FLAG} ${CMAKE_ASM_FLAGS}"
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    ${PROJECT_SOURCE_DIR}/include/openssl/asm_base.h
    ${PROJECT_SOURCE_DIR}/include/openssl/target.h
    ${BCM_SOURCES_ASM_USED}
    DEPENDS
    bcm_c_generated_asm
    delocate
    ${BCM_SOURCES_ASM_USED}
    ${PROJECT_SOURCE_DIR}/include/openssl/arm_arch.h
    ${PROJECT_SOURCE_DIR}/include/openssl/asm_base.h
    ${PROJECT_SOURCE_DIR}/include/openssl/target.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

  add_library(bcm_hashunset STATIC bcm-delocated.S)
  set_target_properties(bcm_hashunset PROPERTIES POSITION_INDEPENDENT_CODE ON)
  set_target_properties(bcm_hashunset PROPERTIES LINKER_LANGUAGE C)

  go_executable(inject_hash
                boringssl.googlesource.com/boringssl/util/fipstools/inject_hash)
  add_custom_command(
    OUTPUT bcm.o
    COMMAND ./inject_hash -o bcm.o -in-archive $<TARGET_FILE:bcm_hashunset>
    DEPENDS bcm_hashunset inject_hash
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set(CRYPTO_FIPS_OBJECTS bcm.o)
elseif(FIPS_SHARED)
  if(NOT BUILD_SHARED_LIBS)
    message(FATAL_ERROR "FIPS_SHARED set but not BUILD_SHARED_LIBS")
  endif()

  add_library(bcm_library STATIC fipsmodule/bcm.c ${BCM_SOURCES_ASM_USED})
  add_dependencies(bcm_library boringssl_prefix_symbols)
  target_include_directories(bcm_library PRIVATE ${PROJECT_SOURCE_DIR}/include)

  add_custom_command(
    OUTPUT bcm.o
    COMMAND ${CMAKE_LINKER} -r -T ${CMAKE_CURRENT_SOURCE_DIR}/fipsmodule/fips_shared.lds -o bcm.o --whole-archive $<TARGET_FILE:bcm_library>
    DEPENDS bcm_library fipsmodule/fips_shared.lds
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  set(CRYPTO_FIPS_OBJECTS bcm.o)
else()
  add_library(fipsmodule OBJECT fipsmodule/bcm.c ${BCM_SOURCES_ASM_USED})
  add_dependencies(fipsmodule boringssl_prefix_symbols)
  target_include_directories(fipsmodule PRIVATE ${PROJECT_SOURCE_DIR}/include)
  set(CRYPTO_FIPS_OBJECTS $<TARGET_OBJECTS:fipsmodule>)
endif()

add_library(
  crypto

  asn1/a_bitstr.c
  asn1/a_bool.c
  asn1/a_d2i_fp.c
  asn1/a_dup.c
  asn1/a_gentm.c
  asn1/a_i2d_fp.c
  asn1/a_int.c
  asn1/a_mbstr.c
  asn1/a_object.c
  asn1/a_octet.c
  asn1/a_strex.c
  asn1/a_strnid.c
  asn1/a_time.c
  asn1/a_type.c
  asn1/a_utctm.c
  asn1/asn1_lib.c
  asn1/asn1_par.c
  asn1/asn_pack.c
  asn1/f_int.c
  asn1/f_string.c
  asn1/tasn_dec.c
  asn1/tasn_enc.c
  asn1/tasn_fre.c
  asn1/tasn_new.c
  asn1/tasn_typ.c
  asn1/tasn_utl.c
  asn1/posix_time.c
  base64/base64.c
  bio/bio.c
  bio/bio_mem.c
  bio/connect.c
  bio/errno.c
  bio/fd.c
  bio/file.c
  bio/hexdump.c
  bio/pair.c
  bio/printf.c
  bio/socket.c
  bio/socket_helper.c
  blake2/blake2.c
  bn_extra/bn_asn1.c
  bn_extra/convert.c
  buf/buf.c
  bytestring/asn1_compat.c
  bytestring/ber.c
  bytestring/cbb.c
  bytestring/cbs.c
  bytestring/unicode.c
  chacha/chacha.c
  cipher_extra/cipher_extra.c
  cipher_extra/derive_key.c
  cipher_extra/e_aesctrhmac.c
  cipher_extra/e_aesgcmsiv.c
  cipher_extra/e_chacha20poly1305.c
  cipher_extra/e_des.c
  cipher_extra/e_null.c
  cipher_extra/e_rc2.c
  cipher_extra/e_rc4.c
  cipher_extra/e_tls.c
  cipher_extra/tls_cbc.c
  conf/conf.c
  cpu_aarch64_apple.c
  cpu_aarch64_openbsd.c
  cpu_aarch64_fuchsia.c
  cpu_aarch64_linux.c
  cpu_aarch64_sysreg.c
  cpu_aarch64_win.c
  cpu_arm_freebsd.c
  cpu_arm_linux.c
  cpu_intel.c
  crypto.c
  curve25519/curve25519.c
  curve25519/curve25519_64_adx.c
  curve25519/spake25519.c
  des/des.c
  dh_extra/params.c
  dh_extra/dh_asn1.c
  digest_extra/digest_extra.c
  dsa/dsa.c
  dsa/dsa_asn1.c
  ecdh_extra/ecdh_extra.c
  ecdsa_extra/ecdsa_asn1.c
  ec_extra/ec_asn1.c
  ec_extra/ec_derive.c
  ec_extra/hash_to_curve.c
  err/err.c
  engine/engine.c
  evp/evp.c
  evp/evp_asn1.c
  evp/evp_ctx.c
  evp/p_dh.c
  evp/p_dh_asn1.c
  evp/p_dsa_asn1.c
  evp/p_ec.c
  evp/p_ec_asn1.c
  evp/p_ed25519.c
  evp/p_ed25519_asn1.c
  evp/p_hkdf.c
  evp/p_rsa.c
  evp/p_rsa_asn1.c
  evp/p_x25519.c
  evp/p_x25519_asn1.c
  evp/pbkdf.c
  evp/print.c
  evp/scrypt.c
  evp/sign.c
  ex_data.c
  fipsmodule/fips_shared_support.c
  hpke/hpke.c
  hrss/hrss.c
  keccak/keccak.c
  kyber/kyber.c
  lhash/lhash.c
  mem.c
  obj/obj.c
  obj/obj_xref.c
  pem/pem_all.c
  pem/pem_info.c
  pem/pem_lib.c
  pem/pem_oth.c
  pem/pem_pk8.c
  pem/pem_pkey.c
  pem/pem_x509.c
  pem/pem_xaux.c
  pkcs7/pkcs7.c
  pkcs7/pkcs7_x509.c
  pkcs8/pkcs8.c
  pkcs8/pkcs8_x509.c
  pkcs8/p5_pbev2.c
  poly1305/poly1305.c
  poly1305/poly1305_arm.c
  poly1305/poly1305_vec.c
  pool/pool.c
  rand_extra/deterministic.c
  rand_extra/forkunsafe.c
  rand_extra/getentropy.c
  rand_extra/ios.c
  rand_extra/passive.c
  rand_extra/rand_extra.c
  rand_extra/trusty.c
  rand_extra/windows.c
  rc4/rc4.c
  refcount.c
  rsa_extra/rsa_asn1.c
  rsa_extra/rsa_crypt.c
  rsa_extra/rsa_print.c
  spx/address.c
  spx/fors.c
  spx/merkle.c
  spx/spx.c
  spx/thash.c
  spx/spx_util.c
  spx/wots.c
  stack/stack.c
  siphash/siphash.c
  thread.c
  thread_none.c
  thread_pthread.c
  thread_win.c
  trust_token/pmbtoken.c
  trust_token/trust_token.c
  trust_token/voprf.c
  x509/a_digest.c
  x509/a_sign.c
  x509/a_verify.c
  x509/algorithm.c
  x509/asn1_gen.c
  x509/by_dir.c
  x509/by_file.c
  x509/i2d_pr.c
  x509/name_print.c
  x509/policy.c
  x509/rsa_pss.c
  x509/t_crl.c
  x509/t_req.c
  x509/t_x509.c
  x509/t_x509a.c
  x509/v3_akey.c
  x509/v3_akeya.c
  x509/v3_alt.c
  x509/v3_bcons.c
  x509/v3_bitst.c
  x509/v3_conf.c
  x509/v3_cpols.c
  x509/v3_crld.c
  x509/v3_enum.c
  x509/v3_extku.c
  x509/v3_genn.c
  x509/v3_ia5.c
  x509/v3_info.c
  x509/v3_int.c
  x509/v3_lib.c
  x509/v3_ncons.c
  x509/v3_ocsp.c
  x509/v3_pcons.c
  x509/v3_pmaps.c
  x509/v3_prn.c
  x509/v3_purp.c
  x509/v3_skey.c
  x509/v3_utl.c
  x509/x_algor.c
  x509/x_all.c
  x509/x_attrib.c
  x509/x_crl.c
  x509/x_exten.c
  x509/x_name.c
  x509/x_pubkey.c
  x509/x_req.c
  x509/x_sig.c
  x509/x_spki.c
  x509/x_val.c
  x509/x_x509.c
  x509/x_x509a.c
  x509/x509_att.c
  x509/x509_cmp.c
  x509/x509_d2.c
  x509/x509_def.c
  x509/x509_ext.c
  x509/x509_lu.c
  x509/x509_obj.c
  x509/x509_req.c
  x509/x509_set.c
  x509/x509_trs.c
  x509/x509_txt.c
  x509/x509_v3.c
  x509/x509_vfy.c
  x509/x509_vpm.c
  x509/x509.c
  x509/x509cset.c
  x509/x509name.c
  x509/x509rset.c
  x509/x509spki.c
  # TOOD(crbug.com/boringssl/542): Pick up this and the rest of the source list
  # from util/pregenerate.
  ../gen/crypto/err_data.c

  ${CRYPTO_FIPS_OBJECTS}
  ${CRYPTO_SOURCES_ASM_USED}
)
target_include_directories(crypto PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
install_if_enabled(TARGETS crypto EXPORT OpenSSLTargets ${INSTALL_DESTINATION_DEFAULT})
set_property(TARGET crypto PROPERTY EXPORT_NAME Crypto)

if(FIPS_SHARED)
  # Rewrite libcrypto.so to inject the correct module hash value. This assumes
  # UNIX-style library naming, but we only support FIPS mode on Linux anyway.
  add_custom_command(
    TARGET crypto POST_BUILD
    COMMAND ${GO_EXECUTABLE} run
    ${CMAKE_CURRENT_SOURCE_DIR}/../util/fipstools/inject_hash/inject_hash.go
    -o libcrypto.so -in-object libcrypto.so
    # The DEPENDS argument to a POST_BUILD rule appears to be ignored. Thus
    # go_executable isn't used (as it doesn't get built), but we list this
    # dependency anyway in case it starts working in some CMake version.
    DEPENDS ../util/fipstools/inject_hash/inject_hash.go
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

add_dependencies(crypto boringssl_prefix_symbols)
if(WIN32)
  target_link_libraries(crypto ws2_32)
endif()

# CMAKE_SYSTEM_NAME is "Generic" for embedded OSes:
# https://cmake.org/cmake/help/book/mastering-cmake/chapter/Cross%20Compiling%20With%20CMake.html#toolchain-files
#
# For now we assume embedded OSes do not have threads. Additionally, the Threads
# package does not work with Android, but Android does not require any extra
# parameters to link pthreads.
if(NOT CMAKE_SYSTEM_NAME MATCHES "^(Generic|Android)$")
  find_package(Threads REQUIRED)
  target_link_libraries(crypto Threads::Threads)
endif()

# Every target depends on crypto, so we add libcxx as a dependency here to
# simplify injecting it everywhere.
if(USE_CUSTOM_LIBCXX)
  target_link_libraries(crypto libcxx)
endif()
