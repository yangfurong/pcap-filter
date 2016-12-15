#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(pcap-filter, 1.0, yangfurong@ict.ac.cn)
AC_CONFIG_SRCDIR([src/main.c])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(pcap-filter, 1.0)

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_offline])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_UINT8_T

# Checks for library functions.

AC_OUTPUT([Makefile
           src/Makefile
           src/lib/Makefile])
