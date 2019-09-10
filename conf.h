/* conf.h.  Generated automatically by configure.  */
/* conf.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you don't have vprintf but do have _doprnt.  */
/* #undef HAVE_DOPRNT */

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* define if the code is compiled on a UNIX machine */
#define CK_GENERIC 1

/* define if the code is compiled on a Win32 machine */
/* #undef CK_Win32 */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <pthread.h> header file.  */
#define HAVE_PTHREAD_H 1

/* Define if you have the <sgtty.h> header file.  */
#define HAVE_SGTTY_H 1

/* Define if you have the <sys/file.h> header file.  */
#define HAVE_SYS_FILE_H 1

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <termio.h> header file.  */
#define HAVE_TERMIO_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the curses library (-lcurses).  */
/* #undef HAVE_LIBCURSES */

/* Define if you have the dl library (-ldl).  */
/* #undef HAVE_LIBDL */

/* Define if you have the guile library (-lguile).  */
/* #undef HAVE_LIBGUILE */

/* Define if you have the nsl library (-lnsl).  */
/* #undef HAVE_LIBNSL */

/* Define if you have the posix4 library (-lposix4).  */
/* #undef HAVE_LIBPOSIX4 */

/* Define if you have the pthread library (-lpthread).  */
/* #undef HAVE_LIBPTHREAD */

/* Define if you have the readline library (-lreadline).  */
/* #undef HAVE_LIBREADLINE */

/* Define if you have the socket library (-lsocket).  */
/* #undef HAVE_LIBSOCKET */

/* Define if you have the tc_scard library (-ltc_scard).  */
/* #undef HAVE_LIBTC_SCARD */

/* Name of package */
#define PACKAGE "gpkcs11"

/* Version number of package */
#define VERSION "0.7.2"

/* activate and set level of debugging */
/* #undef DEBUG */

/* turn of system assertions */
#define NDEBUG 1

/* activate and set level of debugging */
/* #undef USE_ASSERT */

/* version of OpenSSL which libcrypto is used */
#define CRYPTO_LIB_VERSION 0.9.4

/* major version number of cryptoki that this implements */
#define CRYPTOKI_VERSION_MAJOR 2

/* minor version number of cryptoki that this implements */
#define CRYPTOKI_VERSION_MINOR 01

/* major version number of gpkcs11 */
#define LIBRARY_VERSION_MAJOR 0

/* minor version number of gpkcs11 */
#define LIBRARY_VERSION_MINOR 7

/* patch level of gpkcs11 */
#define TC_LIB_VERSION 2

/*  the maximum number of signals  */
#define MAX_SIG_NUM _NSIG 

/* Threads are activated, C_WaitForSlotEvent will work. */
/* #undef HAVE_THREADING */

/* Threads are activated, C_WaitForSlotEvent will work. */
/* #undef HAVE_THREADING */

/* use an pkcs-11 extension in the OpenSSL lib */
/* #undef HAVE_SC_OPENSSL */

