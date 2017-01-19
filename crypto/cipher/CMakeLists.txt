include_directories(../../include)

if (${ARCH} STREQUAL "x86_64")
  set(
    CIPHER_ARCH_SOURCES

    chacha20_poly1305_x86_64.${ASM_EXT}
  )
endif()

add_library(
  cipher

  OBJECT

  cipher.c
  derive_key.c
  aead.c

  e_null.c
  e_rc2.c
  e_rc4.c
  e_des.c
  e_aes.c
  e_chacha20poly1305.c

  tls_cbc.c
  e_tls.c
  e_ssl3.c

  ${CIPHER_ARCH_SOURCES}
)

add_executable(
  cipher_test

  cipher_test.cc
  $<TARGET_OBJECTS:test_support>
)

add_executable(
  aead_test

  aead_test.cc
  $<TARGET_OBJECTS:test_support>
)

perlasm(chacha20_poly1305_x86_64.${ASM_EXT} asm/chacha20_poly1305_x86_64.pl)

target_link_libraries(cipher_test crypto)
target_link_libraries(aead_test crypto)
add_dependencies(all_tests cipher_test aead_test)
