// Convert DMD CodeView debug information to PDB files
// Copyright (c) 2009-2010 by Rainer Schuetze, All Rights Reserved
//
// License for redistribution is given by the Artistic License 2.0
// see file LICENSE for further details

#include "PEImage.h"

extern "C" {
#include "mscvpdb.h"
}

#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <ctype.h>
#include <direct.h>
#include <share.h>
#include <sys/stat.h>
#include <vector>

#ifdef UNICODE
#define T_sopen	_wsopen
#define T_open	_wopen
#else
#define T_sopen	sopen
#define T_open	open
#endif

///////////////////////////////////////////////////////////////////////
PEImage::PEImage(const TCHAR* iname)
: dump_base(0)
, dump_total_len(0)
, dirHeader(0)
, hdr32(0)
, hdr64(0)
, fd(-1)
, debug_aranges(0)
, debug_pubnames(0)
, debug_pubtypes(0)
, debug_info(0), debug_info_length(0)
, debug_abbrev(0), debug_abbrev_length(0)
, debug_line(0), debug_line_length(0)
, debug_frame(0), debug_frame_length(0)
, debug_str(0)
, debug_loc(0), debug_loc_length(0)
, debug_ranges(0), debug_ranges_length(0)
, debug_macinfo(0), debug_macinfo_length(0)
, debug_addr(0), debug_addr_length(0)
, eh_frame(0), eh_frame_length(0)
, gnu_debuglink(0), gnu_debuglink_length(0)
, codeSegment(0)
, linesSegment(-1)
, reloc(0), reloc_length(0)
, nsec(0)
, nsym(0)
, nimp(0), iimp(0), ithunk(0)
, symtable(0)
, strtable(0)
, bigobj(false)
{
	if(iname)
		loadExe(iname);
}

PEImage::~PEImage()
{
	if(fd != -1)
		_close(fd);
	if(dump_base)
		free_aligned(dump_base);
}

///////////////////////////////////////////////////////////////////////
bool PEImage::readAll(const TCHAR* iname)
{
	if (fd != -1)
		return setError("file already open");

	fd = T_sopen(iname, O_RDONLY | O_BINARY, SH_DENYWR);
	if (fd == -1)
		return setError("Can't open file");

	struct stat s;
	if (fstat(fd, &s) < 0)
		return setError("Can't get size");
	dump_total_len = s.st_size;

	dump_base = alloc_aligned(dump_total_len, 0x1000);
	if (!dump_base)
		return setError("Out of memory");
	if (_read(fd, dump_base, dump_total_len) != dump_total_len)
		return setError("Cannot read file");

	_close(fd);
	fd = -1;
	return true;
}

///////////////////////////////////////////////////////////////////////
bool PEImage::loadExe(const TCHAR* iname)
{
    if (!readAll(iname))
        return false;

	// no shortcut-or, because cygwin gcc emits both "RSDS" CV-Entry with no debug infos
	// and also the dwarf sections with debug infos
    return initCVPtr(true) | initDWARFPtr(true);
}

///////////////////////////////////////////////////////////////////////
bool PEImage::loadObj(const TCHAR* iname)
{
    if (!readAll(iname))
        return false;

    return initDWARFObject();
}

///////////////////////////////////////////////////////////////////////
bool PEImage::save(const TCHAR* oname)
{
	if (fd != -1)
		return setError("file already open");

	if (!dump_base)
		return setError("no data to dump");

	fd = T_open(oname, O_WRONLY | O_CREAT | O_BINARY | O_TRUNC, S_IREAD | S_IWRITE | S_IEXEC);
	if (fd == -1)
		return setError("Can't create file");

	if (_write(fd, dump_base, dump_total_len) != dump_total_len)
		return setError("Cannot write file");

	_close(fd);
	fd = -1;
	return true;
}

///////////////////////////////////////////////////////////////////////
bool PEImage::replaceDebugSection(const void* data, int datalen, bool initCV, bool simulate, int* nsecresult)
{
	// append new debug directory to data
	IMAGE_DEBUG_DIRECTORY debugdir;
	if (dbgDir)
		debugdir = *dbgDir;
	else
		memset(&debugdir, 0, sizeof(debugdir));
	int xdatalen = datalen + sizeof(debugdir);

	// assume there is place for another section because of section alignment
	int newdump_total_len = dump_total_len;
	int s;
	DWORD lastVirtualAddress = 0;
	int firstDWARFsection = -1;
	int cntSections = countSections();
	int symbolTabSection = -1;
	for (s = 0; s < cntSections; s++)
	{
		const char* name = (const char*)sec[s].Name;
		if (name[0] == '/')
		{
			int off = strtol(name + 1, 0, 10);
			name = strtable + off;
		}
		if (strncmp(name, ".symtab", 7) == 0
			&& IMGHDR(FileHeader.PointerToSymbolTable) == sec[s].PointerToRawData)
			symbolTabSection = s;
		else if (strncmp(name, ".debug_", 7) != 0
			&& strncmp(name, ".eh_frame", 9) != 0)
			firstDWARFsection = -1;
		else if (firstDWARFsection < 0)
			firstDWARFsection = s;

		if (strcmp(name, ".debug") == 0)
		{
			if (s == cntSections - 1)
			{
				newdump_total_len = sec[s].PointerToRawData;
				break;
			}
			strcpy((char*)sec[s].Name, ".ddebug");
			printf("warning: .debug not last section, cannot remove section\n");
		}
		lastVirtualAddress = sec[s].VirtualAddress + sec[s].Misc.VirtualSize;
	}

	if (firstDWARFsection > 0)
	{
		if (symbolTabSection > firstDWARFsection)
			symbolTabSection = -1;
		s = firstDWARFsection;
		newdump_total_len = sec[s].PointerToRawData;
		lastVirtualAddress = sec[s - 1].VirtualAddress + sec[s - 1].Misc.VirtualSize;
	}

	if (symbolTabSection == s - 1)
	{
		symbolTabSection = -1;
		s--;
		newdump_total_len = sec[s].PointerToRawData;
		lastVirtualAddress = sec[s - 1].VirtualAddress + sec[s - 1].Misc.VirtualSize;
	}
	else if (symbolTabSection == -1 && symtable && firstDWARFsection <= 0)
	{
		int sizeof_sym = bigobj ? sizeof(IMAGE_SYMBOL_EX) : IMAGE_SIZEOF_SYMBOL;
		newdump_total_len -= nsym * sizeof_sym + *(unsigned long*)strtable;
	}

	if (nsecresult)
		*nsecresult = s + 1;

	if (simulate)
		return true;

	IMGHDR(FileHeader.NumberOfSections) = s + 1;
	nsec = s + 1;
	if (nsec < cntSections)
		memset(sec + nsec, 0, (cntSections - nsec) * sizeof(*sec));
	//else TODO: reserve size for new section header

	int headerlen = dos->e_lfanew + sizeof(IMGHDR(Signature)) +
		sizeof(IMAGE_FILE_HEADER) + IMGHDR(FileHeader.SizeOfOptionalHeader) +
		(nsec * sizeof(*sec));
	int headerdiff = IMGHDR(OptionalHeader.SizeOfHeaders) - headerlen;

	int align = IMGHDR(OptionalHeader.FileAlignment);
	int align_len = xdatalen;
	int fillbefore = 0;
	int fillafter = 0;

	if (align > 0)
	{
		align_len = ((xdatalen + align - 1) / align) * align;
		headerlen = ((headerlen + align - 1) / align) * align;
		headerdiff = IMGHDR(OptionalHeader.SizeOfHeaders) - headerlen;
		int newlen = newdump_total_len - headerdiff;

		fillbefore = (align - (newlen % align)) % align;
		newlen += fillbefore + xdatalen;
		fillafter = (align - (newlen % align)) % align;
	}

	newdump_total_len -= headerdiff;
	newdump_total_len += fillbefore;
	int debugstart = newdump_total_len;
	newdump_total_len += xdatalen;

	int salign_len = xdatalen;
	align = IMGHDR(OptionalHeader.SectionAlignment);
	if (align > 0)
	{
		lastVirtualAddress = ((lastVirtualAddress + align - 1) / align) * align;
		salign_len = ((xdatalen + align - 1) / align) * align;
	}

	int symlen = 0;
	int symstart = 0;
	if (symtable && symbolTabSection == -1)
	{
		int sizeof_sym = bigobj ? sizeof(IMAGE_SYMBOL_EX) : IMAGE_SIZEOF_SYMBOL;
		symlen = nsym * sizeof_sym + *(unsigned long*)strtable;
		newdump_total_len += fillafter;
		symstart = newdump_total_len;
		newdump_total_len += symlen;
		IMGHDR(FileHeader.PointerToSymbolTable) = symstart;
	}
	// reset debug flag to prevent search for .dbg file
	if ((IMGHDR(FileHeader.Characteristics)&IMAGE_FILE_DEBUG_STRIPPED) != 0)
		IMGHDR(FileHeader.Characteristics) &= ~IMAGE_FILE_DEBUG_STRIPPED;

	if (headerdiff != 0)
	{
		for (int i = 0; i < s; i++)
		{
			if (sec[i].PointerToRawData)
				sec[i].PointerToRawData -= headerdiff;
		}
	}

	strcpy((char*)sec[s].Name, ".debug");
	sec[s].Misc.VirtualSize = xdatalen; // union with PhysicalAddress;
	sec[s].VirtualAddress = lastVirtualAddress;
	sec[s].SizeOfRawData = align_len;
	sec[s].PointerToRawData = debugstart;
	sec[s].PointerToRelocations = 0;
	sec[s].PointerToLinenumbers = 0;
	sec[s].NumberOfRelocations = 0;
	sec[s].NumberOfLinenumbers = 0;
	sec[s].Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	// hdr->OptionalHeader.SizeOfImage += salign_len;
	IMGHDR(OptionalHeader.SizeOfImage) = sec[s].VirtualAddress + salign_len;
	IMGHDR(OptionalHeader.SizeOfHeaders) = headerlen;

	IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress) = lastVirtualAddress + datalen;
	IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size) = sizeof(IMAGE_DEBUG_DIRECTORY);

	if (!dbgDir)
	{
		debugdir.Type = 2;
	}

	debugdir.PointerToRawData = sec[s].PointerToRawData;
#if 0
	debugdir.AddressOfRawData = sec[s].PointerToRawData;
	debugdir.SizeOfData = sec[s].SizeOfRawData;
#else // suggested by Z3N
	debugdir.AddressOfRawData = sec[s].VirtualAddress;
	debugdir.SizeOfData = datalen;
#endif

	char* newdata = (char*)alloc_aligned(newdump_total_len, 0x1000);
	if (!newdata)
		return setError("cannot alloc new image");
	// append debug data chunk to existing file image
	memcpy(newdata, dump_base, headerlen);
	memcpy(newdata + headerlen, (char*)dump_base + headerlen + headerdiff, debugstart - fillbefore - headerlen);
	memset(newdata + debugstart - fillbefore, 0, fillbefore);
	memcpy(newdata + debugstart, data, datalen);
	dbgDir = (IMAGE_DEBUG_DIRECTORY*)(newdata + debugstart + datalen);
	memcpy(dbgDir, &debugdir, sizeof(debugdir));
	if (symlen)
	{
		memset(newdata + symstart - fillafter, 0, fillafter);
		memcpy(newdata + symstart, symtable, symlen);
	}
	free_aligned(dump_base);
	dump_base = newdata;
	dump_total_len = newdump_total_len;

	return !initCV || initCVPtr(false);
}

///////////////////////////////////////////////////////////////////////
bool PEImage::initCVPtr(bool initDbgDir)
{
	dos = DPV<IMAGE_DOS_HEADER> (0);
	if(!dos)
		return setError("file too small for DOS header");
	if(dos->e_magic != IMAGE_DOS_SIGNATURE)
		return setError("this is not a DOS executable");

	hdr32 = DPV<IMAGE_NT_HEADERS32> (dos->e_lfanew);
	hdr64 = DPV<IMAGE_NT_HEADERS64> (dos->e_lfanew);
	if(!hdr32)
		return setError("no optional header found");
	if(hdr32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
	   hdr32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
		hdr32 = 0;
	else
		hdr64 = 0;

	if(IMGHDR(Signature) != IMAGE_NT_SIGNATURE)
		return setError("optional header does not have PE signature");
	if(IMGHDR(FileHeader.SizeOfOptionalHeader) < sizeof(IMAGE_OPTIONAL_HEADER32))
		return setError("optional header too small");

	sec = hdr32 ? IMAGE_FIRST_SECTION(hdr32) : IMAGE_FIRST_SECTION(hdr64);
    nsec = IMGHDR(FileHeader.NumberOfSections);

    symtable = DPV<char>(IMGHDR(FileHeader.PointerToSymbolTable));
    nsym = IMGHDR(FileHeader.NumberOfSymbols);
	strtable = symtable + nsym * IMAGE_SIZEOF_SYMBOL;
	initSymbolsMap();

	if(IMGHDR(OptionalHeader.NumberOfRvaAndSizes) <= IMAGE_DIRECTORY_ENTRY_DEBUG)
		return setError("too few entries in data directory");

	nimp = IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if (nimp > 0)
	{
		DWORD off = IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		impDir = RVA<IMAGE_IMPORT_DESCRIPTOR>(off, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!impDir)
		{
			nimp = 0;
			//return setError("import directory not placed in image");
		}
		else
		{
			for (int i = 0; i < nimp; i++)
			{
				if (!impDir[i].Characteristics)
				{
					nimp = i; // end of import directory header
					break;
				}
			}
		}
	}

	unsigned int i;
	int found = false;
	for(i = 0; i < IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size)/sizeof(IMAGE_DEBUG_DIRECTORY); i++)
	{
		int off = IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress) + i*sizeof(IMAGE_DEBUG_DIRECTORY);
		dbgDir = RVA<IMAGE_DEBUG_DIRECTORY>(off, sizeof(IMAGE_DEBUG_DIRECTORY));
		if (!dbgDir)
			continue; //return setError("debug directory not placed in image");
		if (dbgDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
			continue; //return setError("debug directory not of type CodeView");

		cv_base = dbgDir->PointerToRawData;
		OMFSignature* sig = DPV<OMFSignature>(cv_base, dbgDir->SizeOfData);
		if (!sig)
			return setError("invalid debug data base address and size");
		if (memcmp(sig->Signature, "NB09", 4) != 0 && memcmp(sig->Signature, "NB11", 4) != 0)
		{
			// return setError("can only handle debug info of type NB09 and NB11");
			dirHeader = 0;
			dirEntry = 0;
			return true;
		}
		dirHeader = CVP<OMFDirHeader>(sig->filepos);
		if (!dirHeader)
			return setError("invalid CodeView dir header data base address");
		dirEntry = CVP<OMFDirEntry>(sig->filepos + dirHeader->cbDirHeader);
		if (!dirEntry)
			return setError("CodeView debug dir entries invalid");
		return true;
	}

	return setError("no CodeView debug info data found");
}

///////////////////////////////////////////////////////////////////////
bool PEImage::initDWARFPtr(bool initDbgDir)
{
	dos = DPV<IMAGE_DOS_HEADER> (0);
	if(!dos)
		return setError("file too small for DOS header");
	if(dos->e_magic != IMAGE_DOS_SIGNATURE)
		return setError("this is not a DOS executable");

	hdr32 = DPV<IMAGE_NT_HEADERS32> (dos->e_lfanew);
	hdr64 = DPV<IMAGE_NT_HEADERS64> (dos->e_lfanew);
	if(!hdr32)
		return setError("no optional header found");
	if(hdr32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
	   hdr32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
		hdr32 = 0;
	else
		hdr64 = 0;

	if(IMGHDR(Signature) != IMAGE_NT_SIGNATURE)
		return setError("optional header does not have PE signature");
	if(IMGHDR(FileHeader.SizeOfOptionalHeader) < sizeof(IMAGE_OPTIONAL_HEADER32))
		return setError("optional header too small");

	dbgDir = 0;
	sec = hdr32 ? IMAGE_FIRST_SECTION(hdr32) : IMAGE_FIRST_SECTION(hdr64);
	symtable = DPV<char>(IMGHDR(FileHeader.PointerToSymbolTable));
    nsym = IMGHDR(FileHeader.NumberOfSymbols);
	strtable = symtable + nsym * IMAGE_SIZEOF_SYMBOL;

	if (IMGHDR(OptionalHeader.NumberOfRvaAndSizes) <= IMAGE_DIRECTORY_ENTRY_IMPORT)
		return setError("too few entries in data directory");

	nimp = IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if (nimp > 0)
	{
		DWORD off = IMGHDR(OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		impDir = RVA<IMAGE_IMPORT_DESCRIPTOR>(off, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (!impDir)
		{
			nimp = 0;
			//return setError("import directory not placed in image");
		}
		else
		{
			for (int i = 0; i < nimp; i++)
			{
				if (!impDir[i].Characteristics)
				{
					nimp = i; // end of import directory header
					break;
				}
			}
		}
	}

	initDWARFSegments();

	setError(0);
	return true;
}

bool PEImage::initDWARFObject()
{
	IMAGE_FILE_HEADER* hdr = DPV<IMAGE_FILE_HEADER> (0);
	if(!hdr)
		return setError("file too small for COFF header");

	if (hdr->Machine == IMAGE_FILE_MACHINE_UNKNOWN && hdr->NumberOfSections == 0xFFFF)
	{
        static CLSID bigObjClSID = { 0xD1BAA1C7, 0xBAEE, 0x4ba9, { 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8 } };
		ANON_OBJECT_HEADER_BIGOBJ* bighdr = DPV<ANON_OBJECT_HEADER_BIGOBJ> (0);
		if (!bighdr || bighdr->Version < 2 || bighdr->ClassID != bigObjClSID)
			return setError("invalid big object file COFF header");
		sec = (IMAGE_SECTION_HEADER*)((char*)(bighdr + 1) + bighdr->SizeOfData);
        nsec = bighdr->NumberOfSections;
        bigobj = true;
        symtable = DPV<char>(bighdr->PointerToSymbolTable);
        nsym = bighdr->NumberOfSymbols;
	    strtable = symtable + nsym * sizeof(IMAGE_SYMBOL_EX);
	}
    else if (hdr->Machine != IMAGE_FILE_MACHINE_UNKNOWN)
    {
        sec = (IMAGE_SECTION_HEADER*)(hdr + 1);
        nsec = hdr->NumberOfSections;
        bigobj = false;
        hdr32 = (IMAGE_NT_HEADERS32*)((char*)hdr - 4); // skip back over signature
	    symtable = DPV<char>(IMGHDR(FileHeader.PointerToSymbolTable));
        nsym = IMGHDR(FileHeader.NumberOfSymbols);
	    strtable = symtable + nsym * IMAGE_SIZEOF_SYMBOL;
    }
    else
	    return setError("Unknown object file format");

    if (!symtable || !strtable)
	    return setError("Unknown object file format");

	initSymbolsMap();
    initDWARFSegments();
    setError(0);
    return true;
}

void PEImage::initSymbolsMap()
{
	symbols_map.clear();
	int sizeof_sym = bigobj ? sizeof(IMAGE_SYMBOL_EX) : IMAGE_SIZEOF_SYMBOL;
	IMAGE_SYMBOL* sym;
	for (int i = 0; i < nsym; i += 1 + sym->NumberOfAuxSymbols)
	{
		sym = (IMAGE_SYMBOL*)(symtable + i * sizeof_sym);
		SymbolName symname = sym->N.Name.Short == 0 ? SymbolName(strtable + sym->N.Name.Long) : SymbolName(sym->N.ShortName);
		symbols_map.insert({ symname, sym });
		if (symname.HasPrefix())
			symbols_map.insert({ symname.WithoutPrefix(), sym });
		// no use for aux data at the moment
		/*for (int j = 0; j < sym->NumberOfAuxSymbols; j++)
		{
			IMAGE_AUX_SYMBOL* auxsym = (IMAGE_AUX_SYMBOL*)((char*)sym + (j + 1) * sizeof_sym);
		}*/
	}
}

static DWORD sizeInImage(const IMAGE_SECTION_HEADER& sec)
{
    if (sec.Misc.VirtualSize == 0)
        return sec.SizeOfRawData; // for object files
    return sec.SizeOfRawData < sec.Misc.VirtualSize ? sec.SizeOfRawData : sec.Misc.VirtualSize;
}

void PEImage::initDWARFSegments()
{
	for(int s = 0; s < nsec; s++)
	{
		const char* name = (const char*) sec[s].Name;
		if(name[0] == '/')
		{
			int off = strtol(name + 1, 0, 10);
			name = strtable + off;
		}
		if (strcmp(name, ".debug_aranges") == 0)
			debug_aranges = DPV<char>(sec[s].PointerToRawData, sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_pubnames") == 0)
			debug_pubnames = DPV<char>(sec[s].PointerToRawData, sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_pubtypes") == 0)
			debug_pubtypes = DPV<char>(sec[s].PointerToRawData, sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_info") == 0)
			debug_info = DPV<char>(sec[s].PointerToRawData, debug_info_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_abbrev") == 0)
			debug_abbrev = DPV<char>(sec[s].PointerToRawData, debug_abbrev_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_line") == 0)
			debug_line = DPV<char>(sec[linesSegment = s].PointerToRawData, debug_line_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_frame") == 0)
			debug_frame = DPV<char>(sec[s].PointerToRawData, debug_frame_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_str") == 0)
			debug_str = DPV<char>(sec[s].PointerToRawData, sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_loc") == 0)
			debug_loc = DPV<char>(sec[s].PointerToRawData, debug_loc_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_ranges") == 0)
			debug_ranges = DPV<char>(sec[s].PointerToRawData, debug_ranges_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_macinfo") == 0)
			debug_macinfo = DPV<char>(sec[s].PointerToRawData, debug_macinfo_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".debug_addr") == 0)
			debug_addr = DPV<char>(sec[s].PointerToRawData, debug_addr_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".eh_frame") == 0)
			eh_frame = DPV<char>(sec[s].PointerToRawData, eh_frame_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".gnu_debuglink") == 0)
			gnu_debuglink = DPV<char>(sec[s].PointerToRawData, gnu_debuglink_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".reloc") == 0)
			reloc = DPV<char>(sec[s].PointerToRawData, reloc_length = sizeInImage(sec[s]));
		else if (strcmp(name, ".text") == 0)
			codeSegment = s;
	}
}

bool PEImage::relocateDebugLineInfo(unsigned long long img_base)
{
	if(!reloc || !reloc_length)
		return true;

	unsigned long long oldimgbase = getImageBase();
	char* relocbase = reloc;
	char* relocend = reloc + reloc_length;
	while(relocbase < relocend)
	{
		unsigned int virtadr = *(unsigned int *) relocbase;
		unsigned int chksize = *(unsigned int *) (relocbase + 4);

		char* p = RVA<char> (virtadr, 1);
		if(p >= debug_line && p < debug_line + debug_line_length)
		{
			for (unsigned int w = 8; w < chksize; w += 2)
			{
				unsigned short entry = *(unsigned short*)(relocbase + w);
				unsigned short type = (entry >> 12) & 0xf;
				unsigned short off = entry & 0xfff;

				if(type == 3) // HIGHLOW
				{
					if (!isX64())
						*(long*)(p + off) += (DWORD)(img_base - oldimgbase);
					else
						*(long long*)(p + off) += img_base - oldimgbase;
				}
			}
		}
		if(chksize == 0 || chksize >= reloc_length)
			break;
		relocbase += chksize;
	}
	return true;
}

int PEImage::getRelocationInLineSegment(unsigned int offset) const
{
    return getRelocationInSegment(linesSegment, offset);
}

int PEImage::getRelocationInCodeSegment(unsigned int offset) const
{
	return getRelocationInSegment(codeSegment, offset);
}

int PEImage::getRelocationInSegment(int segment, unsigned int offset) const
{
    if (segment < 0)
        return -1;

    int cnt = sec[segment].NumberOfRelocations;
    IMAGE_RELOCATION* rel = DPV<IMAGE_RELOCATION>(sec[segment].PointerToRelocations, cnt * sizeof(IMAGE_RELOCATION));
    if (!rel)
        return -1;

    for (int i = 0; i < cnt; i++)
        if (rel[i].VirtualAddress == offset)
        {
            if (bigobj)
            {
                IMAGE_SYMBOL_EX* sym = (IMAGE_SYMBOL_EX*)(symtable + rel[i].SymbolTableIndex * sizeof(IMAGE_SYMBOL_EX));
                if (!sym)
                    return -1;
                return sym->SectionNumber;
            }
            else
            {
                IMAGE_SYMBOL* sym = (IMAGE_SYMBOL*)(symtable + rel[i].SymbolTableIndex * IMAGE_SIZEOF_SYMBOL);
                if (!sym)
                    return -1;
                return sym->SectionNumber;
            }
        }

    return -1;
}

bool PEImage::hasSectionAtZeroVMA() const
{
	for (int s = 0; s < nsec; s++)
	{
		unsigned long long vma = sec[s].VirtualAddress + getImageBase();
		if (!vma)
			return true;
	}
	return false;
}

unsigned long long PEImage::getSectionVMA(const char* secname) const
{
	for (int s = 0; s < nsec; s++)
	{
		const char* name = (const char*)sec[s].Name;
		if (name[0] == '/')
		{
			int off = strtol(name + 1, 0, 10);
			name = strtable + off;
		}
		if (strcmp(name, secname) == 0)
			return sec[s].VirtualAddress + getImageBase();
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////
struct LineInfoData
{
    int funcoff;
    int funcidx;
    int funcsiz;
    int srcfileoff;
    int npairs;
    int size;
};

struct LineInfoPair
{
    int offset;
    int line;
};

int PEImage::dumpDebugLineInfoCOFF()
{
    char* f3section = 0;
    char* f4section = 0;
	for(int s = 0; s < nsec; s++)
    {
        if (strncmp((char*)sec[s].Name, ".debug$S", 8) == 0)
        {
            DWORD* base = DPV<DWORD>(sec[s].PointerToRawData, sec[s].SizeOfRawData);
            if (!base || *base != 4)
                continue;
            DWORD* end = base + sec[s].SizeOfRawData / 4;
            for (DWORD* p = base + 1; p < end; p += (p[1] + 3) / 4 + 2)
            {
                if (!f4section && p[0] == 0xf4)
                    f4section = (char*)p + 8;
                if (!f3section && p[0] == 0xf3)
                    f3section = (char*)p + 8;
                if (p[0] != 0xf2)
                    continue;

                LineInfoData* info = (LineInfoData*) (p + 2);
                if (p[1] != info->size + 12)
                    continue;

                int* f3off = f4section ? (int*)(f4section + info->srcfileoff) : 0;
                const char* fname = f3off ? f3section + *f3off : "unknown";
                int section = getRelocationInSegment(s, (char*)info - (char*)base);
                const char* secname = findSectionSymbolName(section);
                printf("Sym: %s\n", secname ? secname : "<none>");
                printf("File: %s\n", fname);
                LineInfoPair* pairs = (LineInfoPair*)(info + 1);
                for (int i = 0; i < info->npairs; i++)
                    printf("\tOff 0x%x: Line %d\n", pairs[i].offset, pairs[i].line & 0x7fffffff);
             }
        }
    }
    return 0;
}

int _pstrlen(const BYTE* &p)
{
	int len = *p++;
	if(len == 0xff && *p == 0)
	{
		len = p[1] | (p[2] << 8);
		p += 3;
	}
	return len;
}

unsigned _getIndex(const BYTE* &p)
{
    if (*p & 0x80)
    {
        p += 2;
        return ((p[-2] << 8) | p[-1]) & 0x7fff;
    }
    return *p++;
}

int PEImage::dumpDebugLineInfoOMF()
{
    std::vector<const unsigned char*> lnames;
    std::vector<const unsigned char*> llnames;
    const unsigned char* fname = 0;
    unsigned char* base = (unsigned char*) dump_base;
    if (*base != 0x80) // assume THEADR record
        return -1;
    unsigned char* end = base + dump_total_len;
    for(unsigned char* p = base; p < end; p += *(unsigned short*)(p + 1) + 3)
    {
        switch(*p)
        {
        case 0x80: // THEADR
            fname = p + 3; // pascal string
            break;
        case 0x96: // LNAMES
        {
            int len = *(unsigned short*)(p + 1);
            for(const unsigned char* q = p + 3; q < p + len + 2; q += _pstrlen (q)) // defined behaviour?
                lnames.push_back(q);
            break;
        }
        case 0xCA: // LLNAMES
        {
            int len = *(unsigned short*)(p + 1);
            for(const unsigned char* q = p + 3; q < p + len + 2; q += _pstrlen (q)) // defined behaviour?
                llnames.push_back(q);
            break;
        }
        case 0x95: // LINNUM
        {
            const unsigned char* q = p + 3;
            int basegrp = _getIndex(q);
            int baseseg = _getIndex(q);
            unsigned num = (p + *(unsigned short*)(p + 1) + 2 - q) / 6;
            const unsigned char* fn = fname;
            int flen = fn ? _pstrlen(fn) : 0;
            printf("File: %.*s, BaseSegment %d\n", flen, fn, baseseg);
            for (unsigned int i = 0; i < num; i++)
                printf("\tOff 0x%x: Line %d\n", *(int*)(q + 2 + 6 * i), *(unsigned short*)(p + 6 * i));
            break;
        }
        case 0xc5: // LINSYM
        {
            const unsigned char* q = p + 3;
            unsigned flags = *q++;
            unsigned pubname = _getIndex(q);
            unsigned num = (p + *(unsigned short*)(p + 1) + 2 - q) / 6;
            if (num == 0)
                break;
            const unsigned char* fn = fname;
            int flen = fn ? _pstrlen(fn) : 0;
            const unsigned char* sn = (pubname == 0 || pubname > lnames.size() ? 0 : lnames[pubname-1]);
            int slen = sn ? _pstrlen(sn) : 0;
            printf("Sym: %.*s\n", slen, sn);
            printf("File: %.*s\n", flen, fn);
            for (unsigned i = 0; i < num; i++)
                printf("\tOff 0x%x: Line %d\n", *(int*)(q + 2 + 6 * i), *(unsigned short*)(q + 6 * i));
            break;
        }
        default:
            break;
        }
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////
int PEImage::findSection(unsigned long long off) const
{
	off -= IMGHDR(OptionalHeader.ImageBase);
	for(int s = 0; s < nsec; s++)
		if(sec[s].VirtualAddress <= off && off < sec[s].VirtualAddress + sec[s].Misc.VirtualSize)
			return s;
	return -1;
}

template<typename SYM>
const char* PEImage::t_findSectionSymbolName(int s) const
{
	SYM* sym = 0;
	for(int i = 0; i < nsym; i += 1 + sym->NumberOfAuxSymbols)
	{
		sym = (SYM*) symtable + i;
        if (sym->SectionNumber == s && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
        {
            static char sname[10] = { 0 };

		    if (sym->N.Name.Short == 0)
                return strtable + sym->N.Name.Long;
            return strncpy (sname, (char*)sym->N.ShortName, 8);
        }
	}
    return 0;
}

const char* PEImage::findSectionSymbolName(int s) const
{
    if (s < 0 || s >= nsec)
        return 0;
    if (!(sec[s].Characteristics & IMAGE_SCN_LNK_COMDAT))
        return 0;

    if (bigobj)
        return t_findSectionSymbolName<IMAGE_SYMBOL_EX> (s);
    else
        return t_findSectionSymbolName<IMAGE_SYMBOL> (s);
}

int PEImage::findSymbol(const char* name, unsigned long& off) const
{
	auto it = symbols_map.find(SymbolName(name));
	if (it != symbols_map.end())
	{
		IMAGE_SYMBOL* sym = it->second;
		off = sym->Value;
		return bigobj ? ((IMAGE_SYMBOL_EX*)sym)->SectionNumber - 1 : sym->SectionNumber - 1;
	}
	return -1;
}

int PEImage::findImportSymbol(const char* name, unsigned long& off) const
{
	for (int i = 0; i < nimp; i++)
	{
		IMAGE_IMPORT_DESCRIPTOR* imp = &impDir[i];
		const char* libname = RVA<const char>(imp->Name, 1);
		if (libname)
		{
			IMAGE_THUNK_DATA* origthunk = RVA<IMAGE_THUNK_DATA>(imp->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
			off = imp->FirstThunk;
			while (origthunk && origthunk->u1.Function)
			{
				WORD ordinal;
				const char* funcname = NULL;
				if (IMAGE_SNAP_BY_ORDINAL32(origthunk->u1.Ordinal))
				{
					ordinal = IMAGE_ORDINAL32(origthunk->u1.Ordinal);
					//TODO: check with name?
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* funcimp = RVA<IMAGE_IMPORT_BY_NAME>(origthunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME));
					ordinal = funcimp->Hint;
					funcname = (const char*)&funcimp->Name;
					if (strcmp(funcname, name) == 0 || (funcname[0] == '_' && strcmp(funcname + 1, name) == 0))
					{
						unsigned long long imgoff = off + IMGHDR(OptionalHeader.ImageBase);
						int s = findSection(imgoff);
						if (s == -1)
							return -1;
						off -= sec[s].VirtualAddress;
						return s;
					}
				}
				++origthunk;
				off += sizeof(IMAGE_THUNK_DATA::u1.Function);
			}
		}
	}
	return -1;
}

bool PEImage::getNextImportSymbol(ImportSymbol& sym)
{
	for (;iimp < nimp; iimp++)
	{
		IMAGE_IMPORT_DESCRIPTOR* imp = &impDir[iimp];
		const char* libname = RVA<const char>(imp->Name, 1);
		IMAGE_THUNK_DATA* origthunk = RVA<IMAGE_THUNK_DATA>(imp->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
		if (libname && origthunk)
		{
			sym.libname = libname;
			unsigned long off = imp->FirstThunk;
			origthunk += ithunk;
			off += ithunk * sizeof(IMAGE_THUNK_DATA::u1.Function);
			if (origthunk->u1.Function)
			{
				unsigned long long imgoff = off + IMGHDR(OptionalHeader.ImageBase);
				sym.sec = findSection(imgoff);
				if (sym.sec != -1)
					off -= sec[sym.sec].VirtualAddress;
				sym.off = off;
				if (IMAGE_SNAP_BY_ORDINAL32(origthunk->u1.Ordinal))
				{
					sym.ordinal = IMAGE_ORDINAL32(origthunk->u1.Ordinal);
					sym.symname = NULL;
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* funcimp = RVA<IMAGE_IMPORT_BY_NAME>(origthunk->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME));
					sym.ordinal = funcimp->Hint;
					sym.symname = (const char*)&funcimp->Name;
				}
				++ithunk;
				return true;
			}
			ithunk = 0;
		}
	}
	iimp = 0;
	return false;
}

///////////////////////////////////////////////////////////////////////
int PEImage::countCVEntries() const
{
	return dirHeader ? dirHeader->cDir : 0;
}

OMFDirEntry* PEImage::getCVEntry(int i) const
{
	return dirEntry + i;
}


///////////////////////////////////////////////////////////////////////
// utilities
void* PEImage::alloc_aligned(unsigned int size, unsigned int align, unsigned int alignoff)
{
	if (align & (align - 1))
		return 0;

	unsigned int pad = align + sizeof(void*);
	char* p = (char*) malloc(size + pad);
	if (!p)
		return 0;
	unsigned int off = (align + alignoff - sizeof(void*) - (p - (char*) 0)) & (align - 1);
	char* q = p + sizeof(void*) + off;
	((void**) q)[-1] = p;
	return q;
}

///////////////////////////////////////////////////////////////////////
void PEImage::free_aligned(void* p)
{
	void* q = ((void**) p)[-1];
	free(q);
}
