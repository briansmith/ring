include_directories(../../include)

add_library(
  x509

  OBJECT

  i2d_pr.c
  x509.c
  x_algor.c
  x_all.c
  x_attrib.c
  x_pubkey.c
  x_sig.c
)
