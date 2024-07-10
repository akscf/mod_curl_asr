
include $(top_srcdir)/build/modmake.rulesam

MODNAME=mod_curl_asr
mod_LTLIBRARIES = mod_curl_asr.la
mod_curl_asr_la_SOURCES  = mod_curl_asr.c utils.c curl.c
mod_curl_asr_la_CFLAGS   = $(AM_CFLAGS) -I. -Wno-pointer-arith
mod_curl_asr_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_curl_asr_la_LDFLAGS  = -avoid-version -module -no-undefined -shared

$(am_mod_curl_asr_la_OBJECTS): mod_curl_asr.h

