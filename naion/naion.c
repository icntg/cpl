//go:build ignore

// naion.c is the STB implementation unit for the C library (compiled by C
// clients via `gcc myapp.c naion.c`). The //go:build ignore constraint keeps
// the Go toolchain from trying to compile this .c as part of the pure-Go
// naion package (which has no cgo); C compilers ignore the constraint.
#define NAION_IMPLEMENTATION
#include "naion.h"
