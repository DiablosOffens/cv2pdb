// Convert DMD CodeView debug information to PDB files
// Copyright (c) 2009-2010 by Rainer Schuetze, All Rights Reserved
//
// License for redistribution is given by the Artistic License 2.0
// see file LICENSE for further details

#ifndef __DEMANGLE_H__
#define __DEMANGLE_H__

bool d_demangle(const char* name, char* demangled, int maxlen, bool plain);
bool cpp_demangle(const char* name, char* demangled, int maxlen, bool plain);
bool cpp_ismangled_ctor_dtor_or_conversion(const char* name, bool& ctor, bool& dtor, bool& conversion);

#endif //__DEMANGLE_H__