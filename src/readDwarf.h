#ifndef __READDWARF_H__
#define __READDWARF_H__

#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <assert.h>
#include "mspdb.h"
#include "dwarf.h"

#ifndef _CONST_FUN
#define _CONST_FUN constexpr
#endif

typedef unsigned char byte;

template<typename _Ty,
	typename = std::enable_if<std::is_integral<_Ty>::value && std::is_unsigned<_Ty>::value>::type>
inline _Ty LEB128(byte* &p)
{
	_Ty x = 0;
	int shift = 0;
	byte b;
	do
	{
		b = *p++;
		assert(shift < (sizeof(x) * 8));
		x |= (_Ty)(b & 0x7f) << shift;
		shift += 7;
	} while (b & 0x80);
	return x;
}

template<typename _Ty,
	typename = std::enable_if<std::is_integral<_Ty>::value && std::is_signed<_Ty>::value>::type>
inline _Ty SLEB128(byte* &p)
{
	typedef typename std::_Change_sign<_Ty>::_Unsigned _UTy;
	_UTy x = 0;
	int shift = 0;
	byte b;
	do
	{
		b = *p++;
		assert(shift < (sizeof(x) * 8));
		x |= (_UTy)(b & 0x7f) << shift;
		shift += 7;
	} while (b & 0x80);
	if (shift < (sizeof(x) * 8) && b & 0x40)
		x |= -((_Ty)1 << shift); // sign extend
	return x;
}

inline unsigned int RD2(byte* &p)
{
	unsigned int x = *p++;
	x |= *p++ << 8;
	return x;
}

inline unsigned int RD4(byte* &p)
{
	unsigned int x = *p++;
	x |= *p++ << 8;
	x |= *p++ << 16;
	x |= *p++ << 24;
	return x;
}

inline unsigned long long RD8(byte* &p)
{
	unsigned long long x = *p++;
	for (int shift = 8; shift < 64; shift += 8)
		x |= (unsigned long long) *p++ << shift;
	return x;
}

inline unsigned long long RDsize(byte* &p, int size)
{
	if (size > 8)
		size = 8;
	unsigned long long x = *p++;
	for (int shift = 8; shift < size * 8; shift += 8)
		x |= (unsigned long long) *p++ << shift;
	return x;
}

enum AttrClass
{
	Invalid,
	Addr,
	Block,
	Const,
	String,
	Flag,
	Ref,
	RefSig,
	ExprLoc,
	LinePtr,
	LocListPtr,
	MacPtr,
	RangeListPtr
};

struct DWARF_Attribute
{
	AttrClass type;
	union
	{
		unsigned long long addr;
		struct { byte* ptr; unsigned long long len; } block;
		unsigned long long cons;
		const char* string;
		bool flag;
		byte* ref;
		struct { byte* ptr; unsigned long long len; } expr;
		struct { byte* ptr; unsigned long len; unsigned long long off; } sec_off;
	};

	bool operator==(const DWARF_Attribute& rhs) const
	{
		if (type != rhs.type)
			return false;

		switch (type)
		{
		case Addr:		return addr == rhs.addr;
		case Block:		return block.ptr == rhs.block.ptr && block.len == rhs.block.len;
		case ExprLoc:	return expr.ptr == rhs.expr.ptr && expr.len == rhs.expr.len;
		case Const:
		case RefSig:	return cons == rhs.cons;
		case String:	return string == rhs.string; // use strcmp??
		case Flag:		return flag == rhs.flag;
		case Ref:		return ref == rhs.ref;
		case LinePtr:
		case LocListPtr:
		case MacPtr:
		case RangeListPtr:
			return sec_off.ptr == rhs.sec_off.ptr &&
				sec_off.len == rhs.sec_off.len &&
				sec_off.off == rhs.sec_off.off;
		case Invalid:
		default:
			return true;
		}
	}

	bool operator!=(const DWARF_Attribute& rhs) const
	{
		return !(*this == rhs);
	}
};

///////////////////////////////////////////////////////////////////////////////

#include "pshpack1.h"

#define DWARFHDR(x) (hdr64.sig64 == ~0 ? hdr64.x : hdr32.x)

struct DWARF_CompilationUnit
{
	union {
		struct {
			unsigned int unit_length;
			unsigned short version;
			unsigned int debug_abbrev_offset;
			byte address_size;
		} hdr32;
		struct {
			unsigned int sig64; // = 0xffffffff
			unsigned long long unit_length;
			unsigned short version;
			unsigned long long debug_abbrev_offset;
			byte address_size;
		} hdr64;
	};

	bool isDWARF64() const { return hdr64.sig64 == ~0; }
	int refSize() const { return hdr64.sig64 == ~0 ? 8 : 4; }
	byte addrSize() const { return DWARFHDR(address_size); }
	unsigned short getVersion() const { return DWARFHDR(version); }
	unsigned long long getAbbrevOffset() const { return DWARFHDR(debug_abbrev_offset); }
	unsigned long long getLength() const {
		return hdr64.sig64 != ~0 ? sizeof(hdr32.unit_length) + hdr32.unit_length :
			sizeof(hdr64.sig64) + sizeof(hdr64.unit_length) + hdr64.unit_length;
	}
	bool isInBounds(byte* addr) const { return addr >= (byte*)this && addr < ((byte*)this + getLength()); }
};

struct DWARF_FileName
{
	const char* file_name;
	unsigned int  dir_index;
	unsigned long lastModification;
	unsigned long fileLength;

	void read(byte* &p)
	{
		file_name = (const char*)p;
		p += strlen((const char*)p) + 1;
		unsigned long long index = LEB128<unsigned long long>(p);
		unsigned long long lastmod = LEB128<unsigned long long>(p);
		unsigned long long len = LEB128<unsigned long long>(p);
		assert(index <= UINT32_MAX);
		assert(lastmod <= ULONG_MAX);
		assert(len <= ULONG_MAX);
		dir_index = (unsigned int)index;
		lastModification = (unsigned long)lastmod;
		fileLength = (unsigned long)len;
	}
};

struct DWARF_InfoData
{
	byte* entryPtr;
	unsigned entryOff; // offset in the cu
	unsigned code;
	byte* abbrev;
	unsigned short tag;
	byte hasChild;
	byte* sibling;

	const char* name;
	const char* linkage_name;
	const char* dir;
	const char* producer;
	unsigned short language;
	unsigned long long pclo;
	unsigned long long pchi;
	unsigned long long pcentry;
	unsigned long long default_value;
	byte* type;
	byte* containing_type;
	byte* specification;
	byte* abstract_origin;
	byte* object_pointer;
	byte* import;
	byte* default_value_ref;
	byte* go_key;
	byte* go_elem;
	byte encoding;
	byte ordering;
	byte inlined;
	byte access;
	byte visible;
	byte virtuality;
	byte calling_convention;
	byte go_kind;
	bool haspclo			: 1;
	bool haspchi			: 1;
	bool external			: 1;
	bool declaration		: 1;
	bool merged_from_decl	: 1;
	bool prototyped			: 1;
	bool noreturn			: 1;
	bool artificial			: 1;
	bool explicit_func		: 1;
	bool deleted			: 1;
	bool enum_class			: 1;
	bool all_call_sites		: 1;
	bool all_tail_call_sites : 1;
	bool tail_call			: 1;
	bool isdefault			: 1;	// set if template parameter was defined from default declaration
	DWARF_Attribute location;
	DWARF_Attribute member_location;
	DWARF_Attribute vtable_elem_location;
	DWARF_Attribute frame_base;
	DWARF_Attribute ranges;
	DWARF_Attribute stmt_list;
	DWARF_Attribute call_site_target;
	DWARF_Attribute call_site;
	DWARF_Attribute call_site_data;
	DWARF_Attribute const_value;
	DWARF_Attribute upper_bound;
	DWARF_Attribute lower_bound;
	DWARF_Attribute count;
	DWARF_Attribute byte_size;
	DWARF_Attribute bit_offset;
	DWARF_Attribute bit_size;
	DWARF_Attribute bit_stride;
	DWARF_Attribute string_length;
	DWARF_Attribute return_addr;
	unsigned long long addr_base;
	unsigned long long ranges_base;
	unsigned long decl_column;
	unsigned long decl_file;
	unsigned long decl_line;
	unsigned long call_column;
	unsigned long call_file;
	unsigned long call_line;

	void clear()
	{
		memset(this, 0, sizeof(*this));
#if 0
		entryPtr = 0;
		code = 0;
		abbrev = 0;
		tag = 0;
		hasChild = 0;

		name = 0;
		linkage_name = 0;
		dir = 0;
		producer = 0;
		sibling = 0;
		language = 0;
		encoding = 0;
		pclo = 0;
		pchi = 0;
		pcentry = 0;
		default_value = 0;
		type = 0;
		containing_type = 0;
		specification = 0;
		abstract_origin = 0;
		object_pointer = 0;
		import = 0;
		default_value_ref = 0;
		ordering = 0;
		inlined = 0;
		access = 0;
		visible = 0;
		virtuality = 0;
		calling_convention = 0;
		haspclo = 0;
		haspchi = 0;
		external = 0;
		declaration = 0;
		merged_from_decl = 0;
		prototyped = 0;
		noreturn = 0;
		artificial = 0;
		explicit_func = 0;
		deleted = 0;
		enum_class = 0;
		all_call_sites = 0;
		all_tail_call_sites = 0;
		tail_call = 0;
		isdefault = 0;
		member_location.type = Invalid;
		vtable_elem_location.type = Invalid;
		location.type = Invalid;
		frame_base.type = Invalid;
		ranges.type = Invalid;
		stmt_list.type = Invalid;
		call_site_target.type = Invalid;
		call_site.type = Invalid;
		call_site_data.type = Invalid;
		const_value.type = Invalid;
		upper_bound.type = Invalid;
		lower_bound.type = Invalid;
		count.type = Invalid;
		byte_size.type = Invalid;
		bit_offset.type = Invalid;
		bit_size.type = Invalid;
		bit_stride.type = Invalid;
		string_length.type = Invalid;
		return_addr.type = Invalid;
		addr_base = 0;
		ranges_base = 0;
		decl_column = 0;
		decl_file = 0;
		decl_line = 0;
		call_column = 0;
		call_file = 0;
		call_line = 0;
		//extensions
		go_kind = 0;
		go_key = 0;
		go_elem = 0;
#endif
	}

	bool is_declaration() const { return declaration && !specification; }

	bool operator==(const DWARF_InfoData& rhs) const
	{
#define strfieldequals(field) ((!field && !rhs.field) || \
							  ((field && rhs.field) && !strcmp(field, rhs.field)))
#define fieldequals(field) (field == rhs.field)

		if (!fieldequals(tag)) return false;
		if (!strfieldequals(name)) return false;
		if (!strfieldequals(linkage_name)) return false;
		if (!strfieldequals(dir)) return false;
		if (!strfieldequals(producer)) return false;
		if (!fieldequals(language)) return false;
		if (!fieldequals(encoding)) return false;
		if (!fieldequals(pclo)) return false;
		if (!fieldequals(pchi)) return false;
		if (!fieldequals(pcentry)) return false;
		if (!fieldequals(default_value)) return false;
		if (!fieldequals(type)) return false;
		if (!fieldequals(containing_type)) return false;
		if (!fieldequals(specification)) return false;
		if (!fieldequals(abstract_origin)) return false;
		if (!fieldequals(object_pointer)) return false;
		if (!fieldequals(import)) return false;
		if (!fieldequals(default_value_ref)) return false;
		if (!fieldequals(ordering)) return false;
		if (!fieldequals(inlined)) return false;
		if (!fieldequals(access)) return false;
		if (!fieldequals(visible)) return false;
		if (!fieldequals(virtuality)) return false;
		if (!fieldequals(calling_convention)) return false;
		if (!fieldequals(haspclo)) return false;
		if (!fieldequals(haspchi)) return false;
		if (!fieldequals(external)) return false;
		if (!fieldequals(declaration)) return false;
		if (!fieldequals(prototyped)) return false;
		if (!fieldequals(noreturn)) return false;
		if (!fieldequals(artificial)) return false;
		if (!fieldequals(explicit_func)) return false;
		if (!fieldequals(deleted)) return false;
		if (!fieldequals(enum_class)) return false;
		if (!fieldequals(all_call_sites)) return false;
		if (!fieldequals(all_tail_call_sites)) return false;
		if (!fieldequals(tail_call)) return false;
		if (!fieldequals(isdefault)) return false;
		if (!fieldequals(member_location)) return false;
		if (!fieldequals(vtable_elem_location)) return false;
		if (!fieldequals(location)) return false;
		if (!fieldequals(frame_base)) return false;
		if (!fieldequals(ranges)) return false;
		if (!fieldequals(stmt_list)) return false;
		if (!fieldequals(call_site_target)) return false;
		if (!fieldequals(call_site)) return false;
		if (!fieldequals(call_site_data)) return false;
		if (!fieldequals(const_value)) return false;
		if (!fieldequals(upper_bound)) return false;
		if (!fieldequals(lower_bound)) return false;
		if (!fieldequals(count)) return false;
		if (!fieldequals(byte_size)) return false;
		if (!fieldequals(bit_offset)) return false;
		if (!fieldequals(bit_size)) return false;
		if (!fieldequals(bit_stride)) return false;
		if (!fieldequals(string_length)) return false;
		if (!fieldequals(return_addr)) return false;
		if (!fieldequals(addr_base)) return false;
		if (!fieldequals(ranges_base)) return false;
		if (!fieldequals(decl_column)) return false;
		if (!fieldequals(decl_file)) return false;
		if (!fieldequals(decl_line)) return false;
		if (!fieldequals(call_column)) return false;
		if (!fieldequals(call_file)) return false;
		if (!fieldequals(call_line)) return false;
		//extensions
		if (!fieldequals(go_kind)) return false;
		if (!fieldequals(go_key)) return false;
		if (!fieldequals(go_elem)) return false;

		return true;
#undef strfieldequals
#undef fieldequals
	}

	bool operator!=(const DWARF_InfoData& rhs) const
	{
		return !(*this == rhs);
	}

	void merge(const DWARF_InfoData& id, bool keepCurrent = false)
	{
#define setfield(field) ((id.field) && (!keepCurrent || !(field)))

		if (setfield(name)) name = id.name;
		if (setfield(linkage_name)) linkage_name = id.linkage_name;
		if (setfield(dir)) dir = id.dir;
		if (setfield(producer)) producer = id.producer;
		//if (setfield(sibling)) sibling = id.sibling; // dwarf4 doc: cannot apply
		if (setfield(language)) language = id.language;
		if (setfield(encoding)) encoding = id.encoding;
		if (setfield(pclo)) pclo = id.pclo;
		if (setfield(pchi)) pchi = id.pchi;
		if (setfield(pcentry)) pcentry = id.pcentry;
		if (setfield(default_value)) default_value = id.default_value;
		if (setfield(type)) type = id.type;
		if (setfield(containing_type)) containing_type = id.containing_type;
		if (setfield(specification)) specification = id.specification;
		if (setfield(abstract_origin)) abstract_origin = id.abstract_origin;
		if (setfield(object_pointer)) object_pointer = id.object_pointer;
		if (setfield(import)) import = id.import;
		if (setfield(default_value_ref)) default_value_ref = id.default_value_ref;
		if (setfield(ordering)) ordering = id.ordering;
		if (setfield(inlined)) inlined = id.inlined;
		if (setfield(access)) access = id.access;
		if (setfield(visible)) visible = id.visible;
		if (setfield(virtuality)) virtuality = id.virtuality;
		if (setfield(calling_convention)) calling_convention = id.calling_convention;
		if (setfield(haspclo)) haspclo = id.haspclo;
		if (setfield(haspchi)) haspchi = id.haspchi;
		if (setfield(external)) external = id.external;
		//if (setfield(declaration)) declaration = id.declaration; // dwarf4 doc: cannot apply
		if (setfield(prototyped)) prototyped = id.prototyped;
		if (setfield(noreturn)) noreturn = id.noreturn;
		if (setfield(artificial)) artificial = id.artificial;
		if (setfield(explicit_func)) explicit_func = id.explicit_func;
		if (setfield(deleted)) deleted = id.deleted;
		if (setfield(enum_class)) enum_class = id.enum_class;
		if (setfield(all_call_sites)) all_call_sites = id.all_call_sites;
		if (setfield(all_tail_call_sites)) all_tail_call_sites = id.all_tail_call_sites;
		if (setfield(tail_call)) tail_call = id.tail_call;
		if (setfield(isdefault)) isdefault = id.isdefault;
		if (setfield(member_location.type != Invalid)) member_location = id.member_location;
		if (setfield(vtable_elem_location.type != Invalid)) vtable_elem_location = id.vtable_elem_location;
		if (setfield(location.type != Invalid)) location = id.location;
		if (setfield(frame_base.type != Invalid)) frame_base = id.frame_base;
		if (setfield(ranges.type != Invalid)) ranges = id.ranges;
		if (setfield(stmt_list.type != Invalid)) stmt_list = id.stmt_list;
		if (setfield(call_site_target.type != Invalid)) call_site_target = id.call_site_target;
		if (setfield(call_site.type != Invalid)) call_site = id.call_site;
		if (setfield(call_site_data.type != Invalid)) call_site_data = id.call_site_data;
		if (setfield(const_value.type != Invalid)) const_value = id.const_value;
		if (setfield(upper_bound.type != Invalid)) upper_bound = id.upper_bound;
		if (setfield(lower_bound.type != Invalid)) lower_bound = id.lower_bound;
		if (setfield(count.type != Invalid)) count = id.count;
		if (setfield(byte_size.type != Invalid)) byte_size = id.byte_size;
		if (setfield(bit_offset.type != Invalid)) bit_offset = id.bit_offset;
		if (setfield(bit_size.type != Invalid)) bit_size = id.bit_size;
		if (setfield(bit_stride.type != Invalid)) bit_stride = id.bit_stride;
		if (setfield(string_length.type != Invalid)) string_length = id.string_length;
		if (setfield(return_addr.type != Invalid)) return_addr = id.return_addr;
		if (setfield(addr_base)) addr_base = id.addr_base;
		if (setfield(ranges_base)) ranges_base = id.ranges_base;
		if (setfield(decl_column)) decl_column = id.decl_column;
		if (setfield(decl_file)) decl_file = id.decl_file;
		if (setfield(decl_line)) decl_line = id.decl_line;
		if (setfield(call_column)) call_column = id.call_column;
		if (setfield(call_file)) call_file = id.call_file;
		if (setfield(call_line)) call_line = id.call_line;
		//extensions
		if (setfield(go_kind)) go_kind = id.go_kind;
		if (setfield(go_key)) go_key = id.go_key;
		if (setfield(go_elem)) go_elem = id.go_elem;
		merged_from_decl = id.is_declaration();
#undef setfield
	}
};

struct DWARF_Parameter
{
	const char* name;
	byte* type;
	bool is_this;
	bool is_varargs;
};

struct DWARF_StructMember
{
	enum MemberKind
	{
		Field,
		StaticField,
		BaseClass,
		NestedType,
		TemplateParam,
		Method,
	};

	enum UnnamedType
	{
		Named,
		Constructor,
		Destructor,
		Conversion
	};

	enum Access
	{
		Public = DW_ACCESS_public,
		Private = DW_ACCESS_private,
		Protected = DW_ACCESS_protected
	};

	enum Virtuality
	{
		None = DW_VIRTUALITY_none,
		Virtual = DW_VIRTUALITY_virtual,
		PureVirtual = DW_VIRTUALITY_pure_virtual
	};

	struct MethodInfo
	{
		bool has_this;
		bool comp_gen;
		bool expl;
		Access access;
		Virtuality virt;
		long long virtoff;
		int type;
	};

	MemberKind kind;
	UnnamedType unnamed;
	const char* name;
	long long off;
	int type;
	byte* type_die;
	std::vector<MethodInfo> overloads;
};

#define DWARFHDR_VERSION4(v, new, old) (hdr64.sig64 == ~0 ? (hdr64.v >= 4 ? hdr64.new : hdr64.old) : (hdr32.v >= 4 ? hdr32.new : hdr32.old))
#define DWARFHDR_VERSION4DEFAULT(v, x, d) (hdr64.sig64 == ~0 ? (hdr64.v >= 4 ? hdr64.x : d) : (hdr32.v >= 4 ? hdr32.x : d))

struct DWARF_LineNumberProgramHeader
{
	union {
		struct {
			unsigned int unit_length;
			unsigned short version;
			unsigned int header_length;
			byte minimum_instruction_length;
			byte maximum_operations_per_instruction; // new in DWARF 4
			byte default_is_stmt;
			signed char line_base;
			byte line_range;
			byte opcode_base;
			//byte standard_opcode_lengths[opcode_base]; // number of LEB128-operands
			// string include_directories[] // zero byte terminated
			// DWARF_FileNames file_names[] // zero byte terminated
		} hdr32;
		struct {
			unsigned int sig64; // = 0xffffffff
			unsigned long long unit_length;
			unsigned short version;
			unsigned long long header_length;
			byte minimum_instruction_length;
			byte maximum_operations_per_instruction; // new in DWARF 4
			byte default_is_stmt;
			signed char line_base;
			byte line_range;
			byte opcode_base;
			//byte standard_opcode_lengths[opcode_base]; // number of LEB128-operands
			//const char* include_directories[] // zero byte terminated
			// DWARF_FileNames file_names[] // zero byte terminated
		} hdr64;
	};

	bool isDWARF64() const { return hdr64.sig64 == ~0; }
	unsigned short getVersion() const { return DWARFHDR(version); }
	unsigned long long getLength() const {
		return hdr64.sig64 != ~0 ? sizeof(hdr32.unit_length) + hdr32.unit_length :
			sizeof(hdr64.sig64) + sizeof(hdr64.unit_length) + hdr64.unit_length;
	}
	bool isInBounds(byte* addr) const { return addr >= (byte*)this && addr < ((byte*)this + getLength()); }

	unsigned long long getHeaderLength() const { return DWARFHDR(header_length); }
	byte getMinInstrLength() const { return DWARFHDR(minimum_instruction_length); }

	// versioned fields
	byte getMaxOpsPerInstr() const
	{
		return DWARFHDR_VERSION4DEFAULT(version, maximum_operations_per_instruction, 1);
	}
	byte getDefaultIsStmt() const 
	{
		return DWARFHDR_VERSION4(version, default_is_stmt, maximum_operations_per_instruction);
	}
	signed char getLineBase() const
	{
		return DWARFHDR_VERSION4(version, line_base, default_is_stmt);
	}
	byte getLineRange() const
	{
		return DWARFHDR_VERSION4(version, line_range, line_base);
	}
	byte getOpcodeBase() const
	{
		return DWARFHDR_VERSION4(version, opcode_base, line_range);
	}
	size_t getOffsetForVarArrays() const
	{
		return hdr64.sig64 == ~0 ?
			(hdr64.version >= 4 ? sizeof(hdr64) : sizeof(hdr64) - 1) :
			(hdr32.version >= 4 ? sizeof(hdr32) : sizeof(hdr32) - 1);
	}
};

struct DWARF_LineState
{
	// hdr info
	std::vector<const char*> include_dirs;
	std::vector<DWARF_FileName> files;

	unsigned long long address;
	byte  op_index;
	unsigned int  file;
	unsigned int  line;
	unsigned int  column;
	bool          is_stmt;
	bool          basic_block;
	bool          end_sequence;
	bool          prologue_end;
	bool          epilogue_end;
	unsigned int  isa;
	unsigned int  discriminator;

	// not part of the "documented" state
	DWARF_FileName* file_ptr;
	unsigned long long seg_offset;
	unsigned long section;
	unsigned long long last_addr;
	byte minimum_instruction_length;
	byte maximum_operations_per_instruction;
	std::vector<mspdb::LineInfoEntry> lineInfo;

	DWARF_LineState()
	{
		seg_offset = 0x400000;
		init(0);
	}

	void init(DWARF_LineNumberProgramHeader* hdr)
	{
        section = -1;
		address = 0;
		op_index = 0;
		file = 1;
		line = 1;
		column = 0;
		is_stmt = hdr && hdr->getDefaultIsStmt() != 0;
		basic_block = false;
		end_sequence = false;
		prologue_end = false;
		epilogue_end = false;
		isa = 0;
		discriminator = 0;
		minimum_instruction_length = hdr ? hdr->getMinInstrLength() : 1;
		maximum_operations_per_instruction = hdr ? hdr->getMaxOpsPerInstr() : 1;
	}

	void advance_addr(unsigned long long operation_advance)
	{
		unsigned long long address_advance = minimum_instruction_length * ((op_index + operation_advance) / maximum_operations_per_instruction);
		address += address_advance;
		op_index = (op_index + operation_advance) % maximum_operations_per_instruction;
	}

	void addLineInfo()
	{
#if 0
		const char* fname = (file == 0 ? file_ptr->file_name : files[file - 1].file_name);
		printf("Adr:%08x Line: %5d File: %s\n", address, line, fname);
#endif
		if (address < seg_offset)
			return;
		if ((address - seg_offset) > UINT_MAX)
			return;
		if (line > USHRT_MAX)
			return;
		mspdb::LineInfoEntry entry;
		entry.offset = (unsigned int)(address - seg_offset);
		entry.line = line;
		lineInfo.push_back(entry);
	}
};

#include "poppack.h"

///////////////////////////////////////////////////////////////////////////////

#define DW_REG_CFA 257

struct Piece;

struct Location
{
	enum Type
	{
		Invalid, // Failed to evaluate the location expression
		InReg,   // In register (reg)
		Abs,     // Absolute address (off)
		RegRel,  // Register-relative address ($reg + off)
		Imm,	 // No Location but an immediate value (len + ptr)
		OptOut,  // Only location but no value (optimized out)
		ImplPtr, // No Location but implicit pointer (die_ptr) as value with offset (die_off)
		/* No location, but there is a value constant (expression) in dwarf stack
		Abs ([off, die_off] => stackval)
		RegRel ($reg + off as value expression)
		if combined with Deref, there can't be an offset (valoff)
		to stack value bits, so this (valoff) needs to be added to the value itself */
		InStack = 0x40,
		/* Actual location is stored at underlying location, so it needs to
		be dereferenced, all subsequent ops are applied to the
		derefenced value (for now only addition can be stored as valoff) */
		Deref = 0x80,
		FlagsMask = InStack | Deref
	};

	Type type;
	union {
		struct /* regrel */
		{
			long long off;
			int reg;
		};
		struct /* imm */
		{
			unsigned long long len;
			byte* ptr;
		};
		struct /* implptr */
		{
			long long die_off;
			byte* die_ptr;
		};
		unsigned long long stackval;
	};
	long long valoff; // only for ((InStack ^ Deref) | RegRel) (reg value is not available, it's abstract)
	byte refsize;

	bool operator==(const Location& rhs) const
	{
		if (type != rhs.type)
			return false;

		if (type & FlagsMask)
		{
			if (valoff != rhs.valoff)
				return false;
			if (!!(type & Deref) &&
				refsize != rhs.refsize)
				return false;
		}

		switch (type & (~FlagsMask))
		{
		case InReg:		return reg == rhs.reg;
		case Abs:		return off == rhs.off;
		case RegRel:	return reg == rhs.reg && off == rhs.off;
		case Imm:		return len == rhs.len && ptr == rhs.ptr;
		case ImplPtr:	return die_off == rhs.die_off && die_ptr == rhs.die_ptr;
		case Invalid:
		case OptOut:
		default:
			return true;
		}
	}

	bool operator!=(const Location& rhs) const
	{
		return !(*this == rhs);
	}

	void prepareForHashing()
	{
		// reset all now unused fields to zero

		if (type & FlagsMask)
		{
			if (!(type & Deref))
				refsize = 0;
		}
		else
		{
			valoff = 0;
			refsize = 0;
		}

		const size_t rem = sizeof(ptr) - sizeof(reg);
		switch (type & (~FlagsMask))
		{
		case InReg:
			off = 0;
			if (rem > 0)
				memset((char*)&reg + sizeof(reg), 0, rem);
			break;
		case Abs:
			ptr = 0;
			break;
		case RegRel:	
			if (rem > 0)
				memset((char*)&reg + sizeof(reg), 0, rem);
			break;
		case Imm:
		case ImplPtr:
			break;
		case Invalid:
		case OptOut:
		default:
			len = 0;
			ptr = 0;
			break;
		}
	}

	bool is_invalid() const { return type == Invalid; }
	bool is_inreg() const { return type == InReg; }
	bool is_abs() const { return type == Abs; }
	bool is_regrel() const { return type == RegRel; }
	bool is_imm() const { return type == Imm; }
	bool is_optout() const { return type == OptOut; }
	bool is_implptr() const { return type == ImplPtr; }
	bool is_instack() const { return !!(type & InStack); }
	bool need_deref() const { return !!(type & Deref); }
	// for arithmetic ops (InStack|Abs and InStack|RegRel can only be last op, so no check)
	bool has_stackval() const { return type == Abs || type == RegRel || type == ImplPtr; }
};

struct Piece
{
	Location loc;
	unsigned long long size;
	unsigned long long offset;
};

typedef struct pcRange_t
{
	unsigned long long pclo;
	unsigned long long pchi;
} pcRange_t;

struct CompilationUnitData
{
	enum language
	{
		language_unknown,	/* Language not known */
		language_auto,		/* Placeholder for automatic setting */
		language_c,			/* C */
		language_cplus,		/* C++ */
		language_d,			/* D */
		language_go,		/* Go */
		language_objc,		/* Objective-C */
		language_java,		/* Java */
		language_fortran,	/* Fortran */
		language_m2,		/* Modula-2 */
		language_asm,		/* Assembly language */
		language_pascal,	/* Pascal */
		language_ada,		/* Ada */
		language_opencl,	/* OpenCL */
		language_minimal,	/* All other languages, minimal support only */
		nr_languages
	};

	const DWARF_CompilationUnit* header;
	unsigned long long base_address;/* base address of this cu */
	unsigned long long addr_base;	/* fission extension */
	unsigned long long ranges_base;	/* fission extension */
	language language;
	//byte* base_types;
	const char* name;
	const char* dir;
	const char* producer;
	//byte identifier_case;
	unsigned long long pclo;
	unsigned long long pchi;
	DWARF_Attribute stmt_list;
	//DWARF_Attribute macro_info;
	std::vector<pcRange_t> ranges;
};

struct CallSiteParam
{
	/*
		only 3 types:
		InReg	- dwarf register
		RegRel	- stack pointer offset from caller (reg == RSP|ESP),
				  equal to offset from callee's frame base
		Abs		- DIE offset relative to the start of this CU to
				  DW_TAG_formal_parameter which is referenced by both
				  caller and the callee
	*/
	Location loc;
	DWARF_Attribute value;
	DWARF_Attribute data_value;
};

struct FrameInfoData
{
	enum Type
	{
		Normal,
		/* A fake frame, created by GDB when performing an inferior function
		call.  */
		Dummy,
		/* A frame representing an inlined function, associated with an
		upcoming (prev, outer, older) NORMAL_FRAME.  */
		Inline,
		/* A virtual frame of a tail call - see dwarf2_tailcall_frame_unwind.  */
		Tailcall,
		/* Sentinel or registers frame.  This frame obtains register values
		direct from the inferior's registers.  */
		/* A true stack frame, created by the target program during normal
		execution.  */
		Sentinel
	};

	enum Type type;

	struct FrameId
	{
		unsigned long long stack_addr;
		unsigned long long code_addr;
		unsigned long long special_addr;
	} id;

	/*	The frame's `resume' address.  Where the program will resume in
	this frame.	*/
	unsigned long long pc;
	// The frame's function address
	unsigned long long func;

	Location base; // generic base address location
	Location locals; // base address location of the frame's local variables
	Location args; // base address location of the frame's arguments / parameters

	/* Pointers to the next (down, inner, younger) and previous (up,
	outer, older) frame_info's in the frame cache.  */
	struct FrameInfoData* next; // down, inner, younger
	struct FrameInfoData* prev; // up, outer, older

	bool is_inline() const { return type == Inline; }
};

struct CallSite
{
	enum TargetType
	{
		bitpos,	/**< bitpos */
		enumval,	/**< enumval */
		physaddr,	/**< physaddr */
		physname,	/**< physname */
		dwarf_block	/**< dwarf_block */
	};
	unsigned long long pc;
	int tail_call_func_type; //cv func type for the tail call list
	TargetType target_type;
	union
	{
		int bitpos;
		unsigned enumval;
		unsigned long long physaddr;
		const char* physname;
		DWARF_Attribute block;
	} target;
	CompilationUnitData cu;
	std::vector<CallSiteParam> params;

	unsigned long long getTargetAddr(const FrameInfoData* callerFrame = NULL) const;
	unsigned long long getImportTargetAddr() const;
};

// Location list entry
struct LOCEntry
{
	unsigned long long beg_offset;
	unsigned long long end_offset;
	DWARF_Attribute attr;

	bool eol() const { return beg_offset == 0 && end_offset == 0; }
};

// Base address selection entry
struct BASEntry
{
	BASEntry(unsigned long long max_offset)
		: max_offset(max_offset)
		, valid(false)
	{
	}

	unsigned long long max_offset;
	unsigned long long base_address;
	bool valid;

	bool convertFrom(const LOCEntry& entry)
	{
		if (entry.beg_offset != max_offset)
			return false;
		base_address = entry.end_offset;
		valid = true;
		return true;
	}

	bool isvalid() const { return valid; }
};

// Attemots to partially evaluate DWARF location expressions.
// The only supported expressions are those, whose result may be represented
// as either an absolute value, a register, or a register-relative address.
Location decodeLocation(const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame = 0, int at = 0, long long offset = 0);
typedef std::map<pcRange_t, Location> locListMap_t;
locListMap_t decodeLocationList(const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame = 0, long long valoff = 0);
bool decodeRanges(const DWARF_Attribute& attr, pcRange_t* minmax, const CompilationUnitData& cu, std::vector<pcRange_t>* ranges);

class PEImage;

// Debug Information Entry Cursor
class DIECursor
{
public:
	CompilationUnitData cu;
	byte* ptr;
	byte* lastptr;
	int level;
	bool hasChild; // indicates whether the last read DIE has children
	byte* sibling;
	const class DIECursor* parentCursor;

	byte* getDWARFAbbrev(unsigned long long off, unsigned findcode);

private:
	DIECursor() : level(-1) { }

public:
	static const DIECursor Invalid;
	static void setContext(const PEImage* img_, const PEImage* dbgimg_);

	// Create a new DIECursor
	DIECursor(const DWARF_CompilationUnit* cu_);

	// Returns 'true' if the cursor cannot read DIEs.
	bool isInvalid();

	// Goto next sibling DIE.  If the last read DIE had any children, they will be skipped over.
	void gotoSibling();
	// Goto first child of the last read DIE (next DIE in physical order) or the child specified by the pointer.
	// If the last read DIE has no such child, stop enumeration.
	// Otherwise enumeration starts with this child and stops after last child.
	// The specified parent cursor can be used to build an enumartion tree.
	void gotoSubtree(byte* childptr = 0, const class DIECursor* parent = 0);

	// Reads next sibling DIE.  If the last read DIE had any children, they will be skipped over.
	// Returns 'false' upon reaching the last sibling on the current level, if stopAtNull is true.
	// Otherwise, it will skip null DIEs and stop only at the end of the subtree for which this DIECursor was created.
	bool readSibling(DWARF_InfoData& id, bool stopAtNull = false);

	// Returns cursor that will enumerate children of the last read DIE.
	// Enumeration starts with the first child or the child specified by the pointer.
	DIECursor getSubtreeCursor(byte* childptr = 0) const &;
	// rvalue not possible for parentCursor! be carefull with calls on a temporary
	DIECursor&& getSubtreeCursor(byte* childptr = 0) && ;

	// Returns cursor that restarts enumeration at the parent DIE before it was read.
	DIECursor getParentCursor() const;

	// Reads the next DIE in physical order, returns 'true' if succeeds.
	// If stopAtNull is true, readNext() will stop upon reaching a null DIE (end of the current tree level).
	// Otherwise, it will skip null DIEs and stop only at the end of the subtree for which this DIECursor was created.
	bool readNext(DWARF_InfoData& id, bool stopAtNull = false, bool skipSpec = false);
	// Read again the last succuessfull read DIE in physical order
	bool readAgain(DWARF_InfoData& id, bool skipSpec = false) const;
};

// Location list cursor
class LOCCursor
{
private:
	const CompilationUnitData& cu;
	byte* beg;
	byte* end;
	byte* ptr;
	BASEntry last_base_entry;
	byte default_address_size;

public:
	LOCCursor(const CompilationUnitData& cu_, byte* section_beg, unsigned long section_len, unsigned long long off);

	unsigned long long baseAddress() const;

	bool readNext(LOCEntry& entry);
};

// iterate over DWARF debug_line information
// if mod is null, print them out, otherwise add to module
bool interpretDWARFLines(const PEImage& img, mspdb::Mod* mod);
bool interpretDWARFLines(const CompilationUnitData& cu, const PEImage& img, mspdb::Mod* mod);
const DIECursor& getCompilationUnitCursor(unsigned long long off);
DIECursor findCompilationUnitChildCursor(byte* addrInside);
CallSite* getCallSiteForPC(unsigned long long pc, bool insert = false);
const CallSite* findCallSiteForTarget(unsigned long long target);

#define MAKEFLAGSENUMUNOP(type, op) \
inline _CONST_FUN type operator##op(type a) \
{ \
return static_cast<type>(op static_cast<unsigned>(a)); \
} \

#define MAKEFLAGSENUMBINOP(type, op) \
inline _CONST_FUN type operator##op(type a, type b) \
{ \
return static_cast<type>(static_cast<unsigned>(a) op static_cast<unsigned>(b)); \
} \
static_assert(sizeof(type) == sizeof(unsigned), "enum is not size of unsigned int"); \
inline type& operator##op=(type& a, type b) \
{ \
return (type&)(((unsigned&)a) op= ((unsigned)b)); \
} \

#define MAKEFLAGSENUM(type) \
	MAKEFLAGSENUMBINOP(type, |) \
	MAKEFLAGSENUMBINOP(type, &) \
	MAKEFLAGSENUMBINOP(type, ^) \
	MAKEFLAGSENUMUNOP(type, ~) \

MAKEFLAGSENUM(Location::Type)

//on windows:
//#include <windows.h>
//DEFINE_ENUM_FLAG_OPERATORS(Location::Type)

// declare hasher for DWARF_InfoData
_STD_BEGIN
template<>
struct hash<DWARF_InfoData>
{
	size_t operator()(const DWARF_InfoData& val) const
	{
		// unique pointer is a good hash value
		return (size_t)val.entryPtr; // std::hash<byte*>()(val.entryPtr);
	}
};
template<>
struct hash<Location>
	: public _Bitwise_hash<Location>
{
	typedef Location _Kty;
	typedef _Bitwise_hash<Location> _Mybase;

	size_t operator()(const _Kty& _Keyval) const
	{
		Location temp = _Keyval;
		temp.prepareForHashing();
		return (_Mybase::operator()(temp));
	}
};
template<>
struct equal_to<DWARF_InfoData>
{	// functor for operator==
	typedef DWARF_InfoData first_argument_type;
	typedef DWARF_InfoData second_argument_type;
	typedef bool result_type;

	_CONST_FUN bool operator()(const DWARF_InfoData& _Left, const DWARF_InfoData& _Right) const
	{	// apply operator== to operands
		return (_Left.entryPtr == _Right.entryPtr);
	}
};

template<>
struct less<pcRange_t>
{	// functor for operator<
	typedef pcRange_t first_argument_type;
	typedef pcRange_t second_argument_type;
	typedef bool result_type;

	_CONST_FUN bool operator()(const pcRange_t& _Left, const pcRange_t& _Right) const
	{	// apply operator< to operands
		// special: greater ranges comes first if the lower bounds are equal
		return (_Left.pclo < _Right.pclo || (_Left.pclo == _Right.pclo && _Left.pchi > _Right.pchi));
	}
};
_STD_END

#endif
