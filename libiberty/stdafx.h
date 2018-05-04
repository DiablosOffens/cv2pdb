// stdafx.h: Includedatei für Standardsystem-Includedateien
// oder häufig verwendete projektspezifische Includedateien,
// die nur in unregelmäßigen Abständen geändert werden.
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Selten verwendete Komponenten aus Windows-Headern ausschließen

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
void * malloc();
void * realloc();
extern long strtol(const char *nptr, char **endptr, int base);
extern double strtod(const char *nptr, char **endptr);
#endif
#include <sys/types.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#else
# ifndef alloca
#  ifdef __GNUC__
#   define alloca __builtin_alloca
#  else
#   include <malloc.h>
#  endif /* __GNUC__ */
# endif /* alloca */
#endif /* HAVE_ALLOCA_H */

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifndef INT_MAX
# define INT_MAX       (int)(((unsigned int) ~0) >> 1)          /* 0x7FFFFFFF */ 
#endif


// TODO: Hier auf zusätzliche Header, die das Programm erfordert, verweisen.
