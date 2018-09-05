include_directories(../../include)

add_library(
  cipher_extra

  OBJECT

  cipher_extra.c
  derive_key.c

  e_null.c
  e_rc2.c
  e_rc4.c
  e_aesgcmsiv.c
  e_aesctrhmac.c
  e_aesccm.c
  e_chacha20poly1305.c

  tls_cbc.c
  e_tls.c
)
