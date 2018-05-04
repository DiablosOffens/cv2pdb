// Convert DMD CodeView debug information to PDB files
// Copyright (c) 2009-2010 by Rainer Schuetze, All Rights Reserved
//
// License for redistribution is given by the Artistic License 2.0
// see file LICENSE for further details

#ifndef __PEIMAGE_H__
#define __PEIMAGE_H__

#include "LastError.h"

#include <windows.h>
#include <unordered_map>

struct OMFDirHeader;
struct OMFDirEntry;

struct ImportSymbol
{
	const char* libname;
	const char* symname; // name of symbol if it is not an import by ordinal #
	unsigned short ordinal;

	// section+offset to the IAT entry
	struct
	{
		int sec;
		unsigned long off;
	};
};

struct SymbolName
{
	const char* name;
	size_t len;

	template <size_t size>
	SymbolName(const BYTE(&val)[size])
		: name((const char*)val), len(strnlen((const char*)val, size))
	{
	}
	SymbolName(const char* val)
		: name(val), len(strlen(val))
	{
	}

	bool HasPrefix() const { return name[0] == '_'; }

	SymbolName WithoutPrefix() const
	{
		SymbolName result = *this;
		result.name += 1;
		result.len -= 1;
		return result;
	}
};

#ifndef _CONST_FUN
#define _CONST_FUN constexpr
#endif

_STD_BEGIN
template<>
struct hash<SymbolName>
{
	size_t operator()(const SymbolName& _Keyval) const
	{
		return _Hash_seq((const unsigned char*)_Keyval.name, _Keyval.len);
	}
};
template<>
struct equal_to<SymbolName>
{	// functor for operator==
	typedef SymbolName first_argument_type;
	typedef SymbolName second_argument_type;
	typedef bool result_type;

	_CONST_FUN bool operator()(const SymbolName& _Left, const SymbolName& _Right) const
	{	// apply operator== to operands
		return (_Left.len == _Right.len && strncmp(_Left.name, _Right.name, _Left.len) == 0);
	}
};
_STD_END

#define IMGHDR(x) (hdr32 ? hdr32->x : hdr64->x)

class PEImage : public LastError
{
public:
	PEImage(const TCHAR* iname = 0);
	~PEImage();

	template<class P> P* DP(int off) const
	{
		return (P*) ((char*) dump_base + off);
	}
	template<class P> P* DPV(int off, int size) const
	{
		if(off < 0 || off + size > dump_total_len)
			return 0;
		return (P*) ((char*) dump_base + off);
	}
	template<class P> P* DPV(int off) const
	{
		return DPV<P>(off, sizeof(P));
	}
	template<class P> P* CVP(int off) const
	{
		return DPV<P>(cv_base + off, sizeof(P));
	}

	template<class P> P* RVA(unsigned long rva, int len) const
	{
		IMAGE_DOS_HEADER *dos = DPV<IMAGE_DOS_HEADER> (0);
		IMAGE_NT_HEADERS32* hdr = DPV<IMAGE_NT_HEADERS32> (dos->e_lfanew);
		IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(hdr);

		for (int i = 0; i < hdr->FileHeader.NumberOfSections; i++)
		{
			if (rva       >= sec[i].VirtualAddress &&
				rva + len <= sec[i].VirtualAddress + sec[i].SizeOfRawData)
				return DPV<P>(sec[i].PointerToRawData + rva - sec[i].VirtualAddress, len);
		}
		return 0;
	}

	bool readAll(const TCHAR* iname);
	bool loadExe(const TCHAR* iname);
	bool loadObj(const TCHAR* iname);
	bool save(const TCHAR* oname);

	bool replaceDebugSection(const void* data, int datalen, bool initCV, bool simulate = false, int* nsecresult = 0);
	bool initCVPtr(bool initDbgDir);
	bool initDWARFPtr(bool initDbgDir);
    bool initDWARFObject();
    void initDWARFSegments();
	void initSymbolsMap();
	bool relocateDebugLineInfo(unsigned long long img_base);

	bool hasDWARF() const { return debug_line != 0; }
	bool hasGNUDebugLink() const { return gnu_debuglink != 0; }
	bool isX64() const { return hdr64 != 0; }

	int countCVEntries() const;
	OMFDirEntry* getCVEntry(int i) const;

	int getCVSize() const { return dbgDir->SizeOfData; }

	// utilities
	static void* alloc_aligned(unsigned int size, unsigned int align, unsigned int alignoff = 0);
	static void free_aligned(void* p);

	int countSections() const { return nsec; }
	int findSection(unsigned long long off) const;
	int findSymbol(const char* name, unsigned long& off) const;
	int findImportSymbol(const char * name, unsigned long& off) const;
	const char* findSectionSymbolName(int s) const;
	const IMAGE_SECTION_HEADER& getSection(int s) const { return sec[s]; }
	unsigned long long getImageBase() const { return IMGHDR(OptionalHeader.ImageBase); }
    int getRelocationInLineSegment(unsigned int offset) const;
	int getRelocationInCodeSegment(unsigned int offset) const;
    int getRelocationInSegment(int segment, unsigned int offset) const;
	unsigned long long getSectionVMA(int s) const { return sec[s].VirtualAddress + getImageBase(); }
	unsigned long long getSectionVMA(const char* secname) const;
	bool getNextImportSymbol(ImportSymbol& sym);
	bool hasSectionAtZeroVMA() const;

    int dumpDebugLineInfoCOFF();
    int dumpDebugLineInfoOMF();

private:
    template<typename SYM> const char* t_findSectionSymbolName(int s) const;

	int fd;
	void* dump_base;
	int dump_total_len;

	// codeview
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS32* hdr32;
	IMAGE_NT_HEADERS64* hdr64;
	IMAGE_SECTION_HEADER* sec;
	IMAGE_IMPORT_DESCRIPTOR* impDir;
	IMAGE_DEBUG_DIRECTORY* dbgDir;
	OMFDirHeader* dirHeader;
	OMFDirEntry* dirEntry;
    int nsec;
    int nsym;
	int nimp, iimp, ithunk;
    const char* symtable;
    const char* strtable;
    bool bigobj;
	std::unordered_map<SymbolName, IMAGE_SYMBOL*> symbols_map;

public:
	//dwarf
	char* debug_aranges;
	char* debug_pubnames;
	char* debug_pubtypes;
	char* debug_info;     unsigned long debug_info_length;
	char* debug_abbrev;   unsigned long debug_abbrev_length;
	char* debug_line;     unsigned long debug_line_length;
	char* debug_frame;    unsigned long debug_frame_length;
	char* debug_str;
	char* debug_loc;      unsigned long debug_loc_length;
	char* debug_ranges;   unsigned long debug_ranges_length;
	char* debug_macinfo;  unsigned long debug_macinfo_length;
	char* debug_addr;	  unsigned long debug_addr_length;
	char* eh_frame;		  unsigned long eh_frame_length;
	char* gnu_debuglink;  unsigned long gnu_debuglink_length;
	char* reloc;          unsigned long reloc_length;

	int linesSegment;
	int codeSegment;
	int cv_base;
};


#endif //__PEIMAGE_H__
