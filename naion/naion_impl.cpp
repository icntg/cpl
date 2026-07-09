// STB-style implementation unit for the naion single-header library.
// Include this .cpp in exactly one translation unit to emit naion's
// definitions. naion.h is portable C and compiles cleanly as C++.
//
// (naion.c carries `//go:build ignore` so the Go toolchain skips it; this
//  .cpp is the C++ implementation TU consumed by cpl_test.)

#define NAION_IMPLEMENTATION
#include "naion.h"
