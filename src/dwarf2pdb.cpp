// Convert DMD CodeView/DWARF debug information to PDB files
// Copyright (c) 2009-2012 by Rainer Schuetze, All Rights Reserved
//
// License for redistribution is given by the Artistic License 2.0
// see file LICENSE for further details
//
// todo:
//  display associative array
//  64 bit:
//   - arguments passed by register
//   - real

#include "cv2pdb.h"
#include "PEImage.h"
#include "symutil.h"
#include "cvutil.h"
#include "demangle.h"

#include "dwarf.h"
#include "go.h"

#include <assert.h>
#include <string>
#include <strstream>
#include <vector>
#include <algorithm>
#include <numeric>

#define FULL_CONTRIB 0

typedef struct nameTypeKey_t
{
	const char* name;
	int type;
	unsigned short tag;
} nameTypeKey_t;

_STD_BEGIN
template<>
struct hash<nameTypeKey_t>
	: public _Bitwise_hash<std::tuple<size_t, int, unsigned short>>
{
	typedef nameTypeKey_t _Kty;
	typedef _Bitwise_hash<std::tuple<size_t, int, unsigned short>> _Mybase;

	size_t operator()(const _Kty& _Keyval) const
	{
		return (_Mybase::operator()(
			std::make_tuple(hash_value(_Keyval.name), _Keyval.type, _Keyval.tag)));
	}
};

template<>
struct hash<void*>
{
	typedef void* _Kty;

	size_t operator()(const _Kty& _Keyval) const
	{
		return hash_value(_Keyval);
	}
};

template<>
struct equal_to<nameTypeKey_t>
{	// functor for operator==
	typedef nameTypeKey_t first_argument_type;
	typedef nameTypeKey_t second_argument_type;
	typedef bool result_type;

	bool operator()(const first_argument_type& _Left, const second_argument_type& _Right) const
	{	// apply operator== to operands
		return _Left.tag == _Right.tag && _Left.type == _Right.type && !strcmp(_Left.name, _Right.name);
	}
};

template<class C, class T>
auto contains(const C& v, const T& x)
-> decltype(end(v), true)
{
	return end(v) != find(begin(v), end(v), x);
}
_STD_END

// wrap templated element type with named struct to prevent warning C4503
// typedefs alone do not collapse the name of the symbol
typedef struct rangeVarMapValue_t
{
	bool external;
	byte* die_ptr;
	//HACK: go can not define live ranges, it defines multiple locations
	// for the same block variable (possibly multiple but equal definitions in source).
	// PDB allows multiple location definitions, but this means not necessarily that a debugger
	// can handle this
	std::unordered_map<Location, std::set<pcRange_t>> map;
} rangeVarMapValue_t;

// wrap templated element type with named struct to prevent warning C4503
// typedefs alone do not collapse the name of the symbol
typedef struct rangeVarMap_t
{
	std::unordered_map<nameTypeKey_t, rangeVarMapValue_t> map;
} rangeVarMap_t;
// wrap templated element type with named struct to prevent warning C4503
// typedefs alone do not collapse the name of the symbol
typedef struct blockVarMap_t
{
	std::map<pcRange_t, rangeVarMap_t> map;
} blockVarMap_t;
typedef std::map<pcRange_t, blockVarMap_t> blockMap_t;

template<typename vtype>
constexpr int num_digits(vtype x, unsigned b)
{
	return x < vtype(0) ? 1 + num_digits(-std::_Change_sign<vtype>::_Signed(x), b) :
		std::_Change_sign<vtype>::_Unsigned(x) < b ? 1 : 1 + num_digits(x / b, b);
}

void CV2PDB::checkDWARFTypeAlloc(int size, int add)
{
	if (cbDwarfTypes + size > allocDwarfTypes)
	{
		//allocDwarfTypes += size + add;
		allocDwarfTypes += allocDwarfTypes / 2 + size + add;
		dwarfTypes = (BYTE*)safe_realloc(dwarfTypes, allocDwarfTypes);
	}
}

enum CV_X86_REG
{
	CV_REG_NONE = 0,
	CV_REG_EAX = 17,
	CV_REG_ECX = 18,
	CV_REG_EDX = 19,
	CV_REG_EBX = 20,
	CV_REG_ESP = 21,
	CV_REG_EBP = 22,
	CV_REG_ESI = 23,
	CV_REG_EDI = 24,
	CV_REG_ES = 25,
	CV_REG_CS = 26,
	CV_REG_SS = 27,
	CV_REG_DS = 28,
	CV_REG_FS = 29,
	CV_REG_GS = 30,

	CV_REG_IP = 31,
	CV_REG_FLAGS = 32,
	CV_REG_EIP = 33,
	CV_REG_EFLAGS = 34,
	CV_REG_ST0 = 128, /* this includes ST1 to ST7 */
	CV_REG_XMM0 = 154, /* this includes XMM1 to XMM7 */
	CV_REG_XMM8 = 252, /* this includes XMM9 to XMM15 */

	// 64-bit regular registers
	CV_AMD64_FLAGS = 31,
	CV_AMD64_RIP = 32,
	CV_AMD64_EFLAGS = 33,
	CV_AMD64_RAX = 328,
	CV_AMD64_RBX = 329,
	CV_AMD64_RCX = 330,
	CV_AMD64_RDX = 331,
	CV_AMD64_RSI = 332,
	CV_AMD64_RDI = 333,
	CV_AMD64_RBP = 334,
	CV_AMD64_RSP = 335,

	// 64-bit integer registers with 8-, 16-, and 32-bit forms (B, W, and D)
	CV_AMD64_R8 = 336,
	CV_AMD64_R9 = 337,
	CV_AMD64_R10 = 338,
	CV_AMD64_R11 = 339,
	CV_AMD64_R12 = 340,
	CV_AMD64_R13 = 341,
	CV_AMD64_R14 = 342,
	CV_AMD64_R15 = 343,

	// Register subset shared by all processor types,
	// must not overlap with any of the ranges below, hence the high values

	CV_ALLREG_ERR = 30000,
	CV_ALLREG_TEB = 30001,
	CV_ALLREG_TIMER = 30002,
	CV_ALLREG_EFAD1 = 30003,
	CV_ALLREG_EFAD2 = 30004,
	CV_ALLREG_EFAD3 = 30005,
	CV_ALLREG_VFRAME = 30006,
	CV_ALLREG_HANDLE = 30007,
	CV_ALLREG_PARAMS = 30008,
	CV_ALLREG_LOCALS = 30009,
	CV_ALLREG_TID = 30010,
	CV_ALLREG_ENV = 30011,
	CV_ALLREG_CMDLN = 30012,
};

static const char* cv_reg_to_string(CV_X86_REG reg, bool isX64)
{
	switch (reg)
	{
	case CV_REG_NONE:	return NULL;
	case CV_REG_EAX:	return "eax";
	case CV_REG_ECX:	return "ecx";
	case CV_REG_EDX:	return "edx";
	case CV_REG_EBX:	return "ebx";
	case CV_REG_ESP:	return "esp";
	case CV_REG_EBP:	return "ebp";
	case CV_REG_ESI:	return "esi";
	case CV_REG_EDI:	return "edi";
	case CV_REG_ES:		return "es";
	case CV_REG_CS:		return "cs";
	case CV_REG_SS:		return "ss";
	case CV_REG_DS:		return "ds";
	case CV_REG_FS:		return "fs";
	case CV_REG_GS:		return "gs";
//	case CV_AMD64_FLAGS:
	case CV_REG_IP:		return isX64 ? "flags" : "ip";
//	case CV_AMD64_RIP:
	case CV_REG_FLAGS:	return isX64 ? "rip" : "flags";
//	case CV_AMD64_EFLAGS:
	case CV_REG_EIP:	return isX64 ? "eflags" : "eip";
	case CV_REG_EFLAGS:	return "eflags";
	case CV_REG_ST0:     case CV_REG_ST0 + 1:
	case CV_REG_ST0 + 2: case CV_REG_ST0 + 3:
	case CV_REG_ST0 + 4: case CV_REG_ST0 + 5:
	case CV_REG_ST0 + 6: case CV_REG_ST0 + 7:
	{
		static char st[sizeof("st0")] = "st0";
		st[2] = '0' + (reg - CV_REG_ST0);
		return st;
	}
	case CV_REG_XMM0:     case CV_REG_XMM0 + 1:
	case CV_REG_XMM0 + 2: case CV_REG_XMM0 + 3:
	case CV_REG_XMM0 + 4: case CV_REG_XMM0 + 5:
	case CV_REG_XMM0 + 6: case CV_REG_XMM0 + 7:
	{
		static char xmm0[sizeof("xmm0")] = "xmm0";
		xmm0[3] = '0' + (reg - CV_REG_XMM0);
		return xmm0;
	}
	case CV_REG_XMM8:     case CV_REG_XMM8 + 1:
	case CV_REG_XMM8 + 2: case CV_REG_XMM8 + 3:
	case CV_REG_XMM8 + 4: case CV_REG_XMM8 + 5:
	case CV_REG_XMM8 + 6: case CV_REG_XMM8 + 7:
	{
		static char xmm8[sizeof("xmm15")] = "xmm15";
		_itoa(8 + (reg - CV_REG_XMM8), &xmm8[3], 10);
		return xmm8;
	}
	case CV_AMD64_RAX:	return "rax";
	case CV_AMD64_RBX:	return "rbx";
	case CV_AMD64_RCX:	return "rcx";
	case CV_AMD64_RDX:	return "rdx";
	case CV_AMD64_RSI:	return "rsi";
	case CV_AMD64_RDI:	return "rdi";
	case CV_AMD64_RBP:	return "rbp";
	case CV_AMD64_RSP:	return "rsp";
	case CV_AMD64_R8:	return "r8";
	case CV_AMD64_R9:	return "r9";
	case CV_AMD64_R10:	return "r10";
	case CV_AMD64_R11:	return "r11";
	case CV_AMD64_R12:	return "r12";
	case CV_AMD64_R13:	return "r13";
	case CV_AMD64_R14:	return "r14";
	case CV_AMD64_R15:	return "r15";
	default:
		return NULL;
	}
	//static const char* regtable[] = {
	//};
}

// defined in gdb/features/i386/i386.c 
enum DWARF_REG32
{
	dwarf_reg32_eax = 0,
	dwarf_reg32_ecx = 1,
	dwarf_reg32_edx = 2,
	dwarf_reg32_ebx = 3,
	dwarf_reg32_esp = 4,
	dwarf_reg32_ebp = 5,
	dwarf_reg32_esi = 6,
	dwarf_reg32_edi = 7,
	dwarf_reg32_eip = 8,
	dwarf_reg32_eflags = 9,
	dwarf_reg32_cs = 10,
	dwarf_reg32_ss = 11,
	dwarf_reg32_ds = 12,
	dwarf_reg32_es = 13,
	dwarf_reg32_fs = 14,
	dwarf_reg32_gs = 15,
	dwarf_reg32_st0 = 16,
	dwarf_reg32_st1 = 17,
	dwarf_reg32_st2 = 18,
	dwarf_reg32_st3 = 19,
	dwarf_reg32_st4 = 20,
	dwarf_reg32_st5 = 21,
	dwarf_reg32_st6 = 22,
	dwarf_reg32_st7 = 23,
	dwarf_reg32_fctrl = 24,
	dwarf_reg32_fstat = 25,
	dwarf_reg32_ftag = 26,
	dwarf_reg32_fiseg = 27,
	dwarf_reg32_fioff = 28,
	dwarf_reg32_foseg = 29,
	dwarf_reg32_fooff = 30,
	dwarf_reg32_fop = 31,
	dwarf_reg32_xmm0 = 32,
	dwarf_reg32_xmm1 = 33,
	dwarf_reg32_xmm2 = 34,
	dwarf_reg32_xmm3 = 35,
	dwarf_reg32_xmm4 = 36,
	dwarf_reg32_xmm5 = 37,
	dwarf_reg32_xmm6 = 38,
	dwarf_reg32_xmm7 = 39,
	dwarf_reg32_mxcsr = 40,
};

// defined in gdb/features/i386/amd64.c 
enum DWARF_REG64
{
	dwarf_reg64_rax = 0,
	dwarf_reg64_rbx = 1,
	dwarf_reg64_rcx = 2,
	dwarf_reg64_rdx = 3,
	dwarf_reg64_rsi = 4,
	dwarf_reg64_rdi = 5,
	dwarf_reg64_rbp = 6,
	dwarf_reg64_rsp = 7,
	dwarf_reg64_r8 = 8,
	dwarf_reg64_r9 = 9,
	dwarf_reg64_r10 = 10,
	dwarf_reg64_r11 = 11,
	dwarf_reg64_r12 = 12,
	dwarf_reg64_r13 = 13,
	dwarf_reg64_r14 = 14,
	dwarf_reg64_r15 = 15,
	dwarf_reg64_rip = 16,
	dwarf_reg64_eflags = 17,
	dwarf_reg64_cs = 18,
	dwarf_reg64_ss = 19,
	dwarf_reg64_ds = 20,
	dwarf_reg64_es = 21,
	dwarf_reg64_fs = 22,
	dwarf_reg64_gs = 23,
	dwarf_reg64_st0 = 24,
	dwarf_reg64_st1 = 25,
	dwarf_reg64_st2 = 26,
	dwarf_reg64_st3 = 27,
	dwarf_reg64_st4 = 28,
	dwarf_reg64_st5 = 29,
	dwarf_reg64_st6 = 30,
	dwarf_reg64_st7 = 31,
	dwarf_reg64_fctrl = 32,
	dwarf_reg64_fstat = 33,
	dwarf_reg64_ftag = 34,
	dwarf_reg64_fiseg = 35,
	dwarf_reg64_fioff = 36,
	dwarf_reg64_foseg = 37,
	dwarf_reg64_fooff = 38,
	dwarf_reg64_fop = 39,
	dwarf_reg64_xmm0 = 40,
	dwarf_reg64_xmm1 = 41,
	dwarf_reg64_xmm2 = 42,
	dwarf_reg64_xmm3 = 43,
	dwarf_reg64_xmm4 = 44,
	dwarf_reg64_xmm5 = 45,
	dwarf_reg64_xmm6 = 46,
	dwarf_reg64_xmm7 = 47,
	dwarf_reg64_xmm8 = 48,
	dwarf_reg64_xmm9 = 49,
	dwarf_reg64_xmm10 = 50,
	dwarf_reg64_xmm11 = 51,
	dwarf_reg64_xmm12 = 52,
	dwarf_reg64_xmm13 = 53,
	dwarf_reg64_xmm14 = 54,
	dwarf_reg64_xmm15 = 55,
	dwarf_reg64_mxcsr = 56,
};

CV_X86_REG dwarf_to_x86_reg(unsigned dwarf_reg)
{
	switch (dwarf_reg)
	{
	case dwarf_reg32_eax: return CV_REG_EAX;
	case dwarf_reg32_ecx: return CV_REG_ECX;
	case dwarf_reg32_edx: return CV_REG_EDX;
	case dwarf_reg32_ebx: return CV_REG_EBX;
	case dwarf_reg32_esp: return CV_REG_ESP;
	case dwarf_reg32_ebp: return CV_REG_EBP;
	case dwarf_reg32_esi: return CV_REG_ESI;
	case dwarf_reg32_edi: return CV_REG_EDI;
	case dwarf_reg32_eip: return CV_REG_EIP;
	case dwarf_reg32_eflags: return CV_REG_EFLAGS;
	case dwarf_reg32_cs: return CV_REG_CS;
	case dwarf_reg32_ss: return CV_REG_SS;
	case dwarf_reg32_ds: return CV_REG_DS;
	case dwarf_reg32_es: return CV_REG_ES;
	case dwarf_reg32_fs: return CV_REG_FS;
	case dwarf_reg32_gs: return CV_REG_GS;

	case dwarf_reg32_st0: case dwarf_reg32_st1:
	case dwarf_reg32_st2: case dwarf_reg32_st3:
	case dwarf_reg32_st4: case dwarf_reg32_st5:
	case dwarf_reg32_st6: case dwarf_reg32_st7:
		return (CV_X86_REG)(CV_REG_ST0 + dwarf_reg - dwarf_reg32_st0);

	case dwarf_reg32_xmm0: case dwarf_reg32_xmm1:
	case dwarf_reg32_xmm2: case dwarf_reg32_xmm3:
	case dwarf_reg32_xmm4: case dwarf_reg32_xmm5:
	case dwarf_reg32_xmm6: case dwarf_reg32_xmm7:
		return (CV_X86_REG)(CV_REG_XMM0 + dwarf_reg - dwarf_reg32_xmm0);
	default:
		return CV_REG_NONE;
	}
}

CV_X86_REG dwarf_to_amd64_reg(unsigned dwarf_reg)
{
	switch (dwarf_reg)
	{
	case dwarf_reg64_rax: return CV_AMD64_RAX;
	case dwarf_reg64_rbx: return CV_AMD64_RBX;
	case dwarf_reg64_rcx: return CV_AMD64_RCX;
	case dwarf_reg64_rdx: return CV_AMD64_RDX;
	case dwarf_reg64_rsi: return CV_AMD64_RSI;
	case dwarf_reg64_rdi: return CV_AMD64_RDI;
	case dwarf_reg64_rbp: return CV_AMD64_RBP;
	case dwarf_reg64_rsp: return CV_AMD64_RSP;
	case dwarf_reg64_r8: return CV_AMD64_R8;
	case dwarf_reg64_r9: return CV_AMD64_R9;
	case dwarf_reg64_r10: return CV_AMD64_R10;
	case dwarf_reg64_r11: return CV_AMD64_R11;
	case dwarf_reg64_r12: return CV_AMD64_R12;
	case dwarf_reg64_r13: return CV_AMD64_R13;
	case dwarf_reg64_r14: return CV_AMD64_R14;
	case dwarf_reg64_r15: return CV_AMD64_R15;
	case dwarf_reg64_rip: return CV_AMD64_RIP;
	case dwarf_reg64_eflags: return CV_AMD64_EFLAGS;
	case dwarf_reg64_cs: return CV_REG_CS;
	case dwarf_reg64_ss: return CV_REG_SS;
	case dwarf_reg64_ds: return CV_REG_DS;
	case dwarf_reg64_es: return CV_REG_ES;
	case dwarf_reg64_fs: return CV_REG_FS;
	case dwarf_reg64_gs: return CV_REG_GS;

	case dwarf_reg64_xmm0: case dwarf_reg64_xmm1:
	case dwarf_reg64_xmm2: case dwarf_reg64_xmm3:
	case dwarf_reg64_xmm4: case dwarf_reg64_xmm5:
	case dwarf_reg64_xmm6: case dwarf_reg64_xmm7:
		return (CV_X86_REG)(CV_REG_XMM0 + dwarf_reg - dwarf_reg64_xmm0);
	case dwarf_reg64_xmm8: case dwarf_reg64_xmm9:
	case dwarf_reg64_xmm10: case dwarf_reg64_xmm11:
	case dwarf_reg64_xmm12: case dwarf_reg64_xmm13:
	case dwarf_reg64_xmm14: case dwarf_reg64_xmm15:
		return (CV_X86_REG)(CV_REG_XMM8 + dwarf_reg - dwarf_reg64_xmm8);
	case dwarf_reg64_st0: case dwarf_reg64_st1:
	case dwarf_reg64_st2: case dwarf_reg64_st3:
	case dwarf_reg64_st4: case dwarf_reg64_st5:
	case dwarf_reg64_st6: case dwarf_reg64_st7:
		return (CV_X86_REG)(CV_REG_ST0 + dwarf_reg - dwarf_reg64_st0);
	default:
		return CV_REG_NONE;
	}
}

static const char* dwarf_reg_to_fpo_reg(unsigned reg, bool isX64)
{
	CV_X86_REG cvreg = isX64 ? dwarf_to_amd64_reg(reg) : dwarf_to_x86_reg(reg);
	if (cvreg == CV_REG_EBP || cvreg == CV_REG_ESP || (!isX64 && cvreg == CV_REG_EIP) ||
		cvreg == CV_AMD64_RBP || cvreg == CV_AMD64_RSP || (isX64 && cvreg == CV_AMD64_RIP))
		return cv_reg_to_string(cvreg, isX64);
	static char result[num_digits(CV_AMD64_R15, 10) + 1];
	_ultoa_s(cvreg, result, 10);
	return result;
}

unsigned char dwarf_to_cv_callconv(unsigned cc)
{
	//TODO: more differentiation
	switch (cc)
	{
	case DW_CC_normal:
	case DW_CC_program:
		return CV_CALL_NEAR_C;
	case DW_CC_nocall:
	default:
		return CV_CALL_RESERVED;
	}
}

unsigned char dwarf_to_cv_lang(enum CompilationUnitData::language lang)
{
	switch (lang)
	{
	case CompilationUnitData::language_c:
		return CV_CFL_C;
	case CompilationUnitData::language_cplus:
		return CV_CFL_CXX;
	case CompilationUnitData::language_java:
		return CV_CFL_JAVA;
	case CompilationUnitData::language_fortran:
		return CV_CFL_FORTRAN;
	case CompilationUnitData::language_asm:
		return CV_CFL_MASM;
	case CompilationUnitData::language_pascal:
		return CV_CFL_PASCAL;
	case CompilationUnitData::language_unknown:
	case CompilationUnitData::language_auto:
	case CompilationUnitData::language_d:
	case CompilationUnitData::language_go:
	case CompilationUnitData::language_objc:
	case CompilationUnitData::language_m2:
	case CompilationUnitData::language_ada:
	case CompilationUnitData::language_opencl:
	case CompilationUnitData::language_minimal:
	default:
		return CV_CFL_C; // pdb needs a value, so fallback
	}
}

__inline unsigned short decodeBasePointerReg(bool isX64, unsigned encodedFrameReg)
{
	static const unsigned short rgFramePointerRegX86[] = {
		CV_REG_NONE, CV_ALLREG_VFRAME, CV_REG_EBP, CV_REG_EBX };
	static const unsigned short rgFramePointerRegX64[] = {
		CV_REG_NONE, CV_AMD64_RSP, CV_AMD64_RBP, CV_AMD64_R13 };

	if (encodedFrameReg >= 4) {
		return CV_REG_NONE;
	}
	if (!isX64) {
		return rgFramePointerRegX86[encodedFrameReg];
	}
	else {
		return rgFramePointerRegX64[encodedFrameReg];
	}
}

__inline unsigned encodeBasePointerReg(unsigned short reg)
{
	switch (reg)
	{
		//TODO: find out what is CV_ALLREG_VFRAME actually in x86 and why is it used and not CV_REG_ESP
	case CV_REG_ESP:
	case CV_ALLREG_VFRAME:
	case CV_AMD64_RSP:
		return 1;
	case CV_REG_EBP:
	case CV_AMD64_RBP:
		return 2;
	case CV_REG_EBX:
	case CV_AMD64_R13:
		return 3;
	default:
		return 0;
	}
}

__inline bool dwarf_preprocess_die(unsigned short tag)
{
	switch (tag)
	{
	case DW_TAG_base_type:
	case DW_TAG_typedef:
	case DW_TAG_pointer_type:
	case DW_TAG_const_type:
	case DW_TAG_volatile_type:
	case DW_TAG_reference_type:
	case DW_TAG_rvalue_reference_type:
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_array_type:
	case DW_TAG_subroutine_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_subrange_type:
	case DW_TAG_string_type:
	case DW_TAG_ptr_to_member_type:
	case DW_TAG_set_type:
	case DW_TAG_file_type:
	case DW_TAG_packed_type:
	case DW_TAG_thrown_type:
	case DW_TAG_restrict_type: // DWARF3
	case DW_TAG_interface_type:
	case DW_TAG_unspecified_type:
	case DW_TAG_mutable_type: // withdrawn
	case DW_TAG_shared_type:
		return true;
	}
	return false;
}

__inline int dwarf_to_cv_fldattr(const DWARF_StructMember::MethodInfo& info, bool is_intro)
{
	int attr = 0;
	switch (info.access)
	{
	case DWARF_StructMember::Public:	attr = CV_fldattr_public; break;
	case DWARF_StructMember::Private:	attr = CV_fldattr_private; break;
	case DWARF_StructMember::Protected:	attr = CV_fldattr_protected; break;
	default:
		assert(false); __assume(false);
	}

	if (!info.has_this)
		attr |= CV_fldattr_MTstatic;
	else if (info.virt != DWARF_StructMember::None)
	{
		if (!is_intro)
			attr |= info.virt == DWARF_StructMember::Virtual ?
			CV_fldattr_MTvirtual : CV_fldattr_MTpurevirt;
		else
			attr |= info.virt == DWARF_StructMember::Virtual ?
			CV_fldattr_MTintro : CV_fldattr_MTpureintro;
	}

	if (info.comp_gen)
		attr |= CV_fldattr_compgenx;

	return attr;
}

// use unsigned short for file? PDB interface may not support higher values
static const char* createUniqueNameForUnnamedType(unsigned short tag, int type, unsigned file)
{
	static char unnamed[sizeof("__unnamed_struct_0001_1234567890")];
	static std::unordered_map<unsigned, int> fileids;
	static std::unordered_map<int, std::pair<unsigned, int>> typeids;
	static const char* kinds[] = { "class", "struct", "union", "enum" };
#define TAGTOKINDROW -1, -1, -1, -1, -1, -1, -1, -1
	static const int mapTagToTypeKinds[] = {
		-1, -1, 0, -1, 3, -1, -1, -1, // 8
		TAGTOKINDROW, // 0x10
		-1, -1, -1, 1, -1, -1, -1, 2, // 0x18
		TAGTOKINDROW, // 0x20
		TAGTOKINDROW, // 0x28
		TAGTOKINDROW, // 0x30
		TAGTOKINDROW, // 0x38
		1
	};
	if (tag < 0 || tag >= _countof(mapTagToTypeKinds))
		return NULL;
	int kind = mapTagToTypeKinds[tag];
	if (kind == -1)
		return NULL;

	int id = 0;
	auto it = typeids.find(type);
	if (it != typeids.end())
	{
		id = it->second.second;
		//don't check for uniqueness, the file id can differ for different CUs but identical files and types
		//just use the first occurrence
		//assert(file == it->second.first);
		file = it->second.first;
	}
	else
		typeids[type] = { file, id = ++fileids[file] };

	int len = snprintf(unnamed, sizeof(unnamed), "__unnamed_%s_%04x_%d", kinds[kind], (unsigned)file, id);
	if (len < 0)
		return NULL; //TODO: better error handling
	return unnamed;
}

// Call Frame Information entry (CIE or FDE)
class CFIEntry
{
public:
	enum Type
	{
		CIE,
		FDE
	};

	byte* ptr;
	byte* end;
	byte type;
	unsigned long long CIE_pointer; //

	// CIE
	byte version;
	const char* augmentation;
	bool saw_z_augmentation;
	bool signal_frame;
	byte fde_encoding;
	byte lsda_encoding;
	byte address_size;
	byte segment_size;
	unsigned long code_alignment_factor;
	long data_alignment_factor;
	unsigned long return_address_register;
	byte* initial_instructions;
	unsigned long initial_instructions_length;

	// FDE
	unsigned long segment;
	unsigned long long initial_location;
	unsigned long long address_range;
	byte* instructions;
	unsigned long instructions_length;
};

// Call Frame Information Cursor
class CFICursor
{
public:
	CFICursor(const PEImage& img, const PEImage& dbgimg, bool eh_frame = false)
		: eh_frame(eh_frame)
		, beg(eh_frame ? (byte*)img.eh_frame : (byte*)dbgimg.debug_frame)
		, end(eh_frame ? (byte*)img.eh_frame + img.eh_frame_length : (byte*)dbgimg.debug_frame + dbgimg.debug_frame_length)
		, ptr(beg)
	{
		section_vma = eh_frame ? img.getSectionVMA(".eh_frame") : dbgimg.getSectionVMA(".debug_frame");
		tbase = img.getSectionVMA(".text");
		dbase = img.getSectionVMA(".got");
		default_address_size = img.isX64() ? 8 : 4;
	}

	bool eh_frame;
	byte* beg;
	byte* end;
	byte* ptr;
	unsigned long long section_vma;
	unsigned long long tbase;
	unsigned long long dbase;
	byte default_address_size;

	static byte
		encoding_for_size(unsigned int size)
	{
		switch (size)
		{
		case 2:	return DW_EH_PE_udata2;
		case 4:	return DW_EH_PE_udata4;
		case 8:	return DW_EH_PE_udata8;
		default:
			assert(false && "Unsupported address size");
			return 0;
		}
	}


	unsigned long long readEncodedValue(byte* &p, byte encoding, byte address_size,
		unsigned long long func_base) const
	{
		ptrdiff_t offset;
		unsigned long long base;

		/* GCC currently doesn't generate DW_EH_PE_indirect encodings for
		FDE's.  */
		if (encoding & DW_EH_PE_indirect)
			assert(false && "Unsupported encoding: DW_EH_PE_indirect");

		switch (encoding & 0x70)
		{
		case DW_EH_PE_absptr:	base = 0; break;
		case DW_EH_PE_pcrel:	base = section_vma; base += (p - beg); break;
		case DW_EH_PE_datarel:	base = dbase; break;
		case DW_EH_PE_textrel:	base = tbase; break;
		case DW_EH_PE_funcrel:	base = func_base; break;
		case DW_EH_PE_aligned:
			base = 0;
			offset = p - beg;
			if ((offset % address_size) != 0)
			{
				p += address_size - (offset % address_size);
			}
			break;
		default:
			assert(false && "Invalid or unsupported encoding");
		}

		if ((encoding & 0x07) == 0x00)
		{
			encoding |= encoding_for_size(address_size);
		}

		switch (encoding & 0x0f)
		{
		case DW_EH_PE_uleb128:
		{
			uint64_t value;
			//const byte *end_buf = p + (sizeof(value) + 1) * 8 / 7;

			value = LEB128<uint64_t>(p);
			return base + value;
		}
		case DW_EH_PE_udata2:	return (base + RD2(p));
		case DW_EH_PE_udata4:	return (base + RD4(p));
		case DW_EH_PE_udata8:	return (base + RD8(p));
		case DW_EH_PE_sleb128:
		{
			int64_t value;
			//const byte *end_buf = p + (sizeof(value) + 1) * 8 / 7;

			value = SLEB128<int64_t>(p);
			return base + value;
		}
		case DW_EH_PE_sdata2:	return (base + (short)RD2(p));
		case DW_EH_PE_sdata4:	return (base + (int)RD4(p));
		case DW_EH_PE_sdata8:	return (base + (long long)RD8(p));
		default:
			assert(false && "Invalid or unsupported encoding");
			return 0;
		}
	}

	bool readCIE(CFIEntry& entry, byte* &p)
	{
		entry.fde_encoding = DW_EH_PE_absptr;
		entry.lsda_encoding = DW_EH_PE_absptr;
		entry.signal_frame = false;
		entry.version = *p++;
		char* augmentation;
		entry.augmentation = augmentation = (char*)p;
		p += strlen(entry.augmentation) + 1;
		if (augmentation[0] == 'e' && augmentation[1] == 'h')
		{
			/* Skip.  */
			p += default_address_size;
			augmentation += 2;
		}

		if (entry.version >= 4)
		{
			entry.address_size = *p++;
			/* Address values in .eh_frame sections are defined to have the
			   target's pointer size */
			if (eh_frame)
				entry.address_size = default_address_size;
			entry.segment_size = *p++;
		}
		else
		{
			entry.address_size = default_address_size;
			entry.segment_size = 0;
		}

		entry.code_alignment_factor = LEB128<unsigned long>(p);
		entry.data_alignment_factor = SLEB128<long>(p);
		entry.return_address_register = entry.version == 1 ? *p++ : LEB128<unsigned long>(p);

		entry.saw_z_augmentation = (*augmentation == 'z');
		if (entry.saw_z_augmentation)
		{
			uint64_t length = LEB128<uint64_t>(p);
			entry.initial_instructions = p + length;
			augmentation++;
		}

		while (*augmentation)
		{
			/* "L" indicates a byte showing how the LSDA pointer is encoded.  */
			if (*augmentation == 'L')
			{
				entry.lsda_encoding = *p++;
				augmentation++;
			}

			/* "R" indicates a byte indicating how FDE addresses are encoded.  */
			else if (*augmentation == 'R')
			{
				entry.fde_encoding = *p++;
				augmentation++;
			}

			/* "P" indicates a personality routine in the CIE augmentation.  */
			else if (*augmentation == 'P')
			{
				/* Skip.  Avoid indirection since we throw away the result.  */
				byte encoding = *p++;
				unsigned long long personality = readEncodedValue(p, encoding & ~DW_EH_PE_indirect, entry.address_size, 0);
				augmentation++;
			}

			/* "S" indicates a signal frame, such that the return
			address must not be decremented to locate the call frame
			info for the previous frame; it might even be the first
			instruction of a function, so decrementing it would take
			us to a different function.  */
			else if (*augmentation == 'S')
			{
				entry.signal_frame = true;
				augmentation++;
			}

			/* Otherwise we have an unknown augmentation.  Assume that either
			there is no augmentation data, or we saw a 'z' prefix.  */
			else
			{
				if (entry.initial_instructions)
					p = entry.initial_instructions;
				break;
			}
		}

		entry.initial_instructions = p;
		entry.initial_instructions_length = 0; // to be calculated outside
		return true;
	}

	bool readHeader(byte* &p, byte* &pend, unsigned long long& CIE_pointer, bool& dwarf64)
	{
		if (p >= end)
			return false;
		long long len = RDsize(p, 4);
		dwarf64 = (len == 0xffffffff);
		int ptrsize = dwarf64 ? 8 : 4;
		if (dwarf64)
			len = RDsize(p, 8);
		if (p + len > end)
			return false;

		pend = p + len;
		CIE_pointer = RDsize(p, ptrsize);
		return true;
	}

	bool readNext(CFIEntry& entry)
	{
		byte* p = ptr;
		bool dwarf64;
		if (!readHeader(p, entry.end, entry.CIE_pointer, dwarf64))
			return false;

		entry.ptr = ptr;

		unsigned long long cie_id;
		if (eh_frame)
			cie_id = 0; // 0 in .eh_frame
		else if (dwarf64)
			cie_id = 0xffffffffffffffffULL;
		else
			cie_id = 0xffffffff;

		if (entry.CIE_pointer == cie_id)
		{
			entry.type = CFIEntry::CIE;
			readCIE(entry, p);
			entry.initial_instructions_length = entry.end - p;
		}
		else
		{
			entry.type = CFIEntry::FDE;

			byte* q, *qend;
			if (eh_frame)
				entry.CIE_pointer = p - beg - entry.CIE_pointer - (dwarf64 ? 8 : 4);
			q = beg + entry.CIE_pointer;
			bool qdwarf64;
			unsigned long long cie_off;
			if (!readHeader(q, qend, cie_off, qdwarf64))
				return false;
			if (!eh_frame && qdwarf64 != dwarf64)
				cie_id = qdwarf64 ? 0xffffffffffffffffULL : 0xffffffff;
			if (cie_off != cie_id)
				return false;
			readCIE(entry, q);
			entry.initial_instructions_length = qend - entry.initial_instructions;

			entry.segment = (unsigned long)(entry.segment_size > 0 ? RDsize(p, entry.segment_size) : 0);
			entry.initial_location = readEncodedValue(p, entry.fde_encoding, entry.address_size, 0);
			entry.address_range = readEncodedValue(p, entry.fde_encoding & 0xf, entry.address_size, 0);
			if (entry.saw_z_augmentation)
			{
				uint64_t length;

				length = LEB128<uint64_t>(p);
				if (p > entry.end)
					return false;
			}
			entry.instructions = p;
			entry.instructions_length = entry.end - p;
		}
		ptr = entry.end;
		return true;
	}
};

static Location mkDerefCFARel(long long off, bool isX64 = false)
{
	Location loc;
	loc.type = Location::Deref | Location::RegRel;
	loc.reg = DW_REG_CFA;
	loc.off = off;
	loc.valoff = 0;
	loc.refsize = isX64 ? 8 : 4; // source reg size
	return loc;
}

static bool isDerefCFARel(const Location& loc)
{
	return (loc.type == (Location::Deref | Location::RegRel)) &&
		loc.reg == DW_REG_CFA;
}

static Location mkCFARel(long long off)
{
	Location loc;
	loc.type = Location::RegRel;
	loc.reg = DW_REG_CFA;
	loc.off = off;
	return loc;
}

static bool isCFARel(const Location& loc)
{
	return loc.type == Location::RegRel && loc.reg == DW_REG_CFA;
}

static Location mkInReg(unsigned reg)
{
	Location loc;
	loc.type = Location::InReg;
	loc.reg = reg;
	return loc;
}

static Location mkAbs(long long off)
{
	Location l;
	l.type = Location::Abs;
	l.off = off;
	return l;
}

static Location mkRegRel(unsigned reg, long long off)
{
	Location l;
	l.type = Location::RegRel;
	l.reg = reg;
	l.off = off;
	return l;
}

struct CFAState
{
	typedef std::unordered_map<int, Location> regRuleMap_t;

	// cumulative for all states
	unsigned long long loc; // virtual program location
	byte* imgloc;			// physical program location
	Location cfa;			// location for current CFA value
	regRuleMap_t savedregs; // rules to save reg (location of previous value)
	int returnreg;			// return address register number (should match the first saved reg)

	// only for current state
	std::vector<int> restoredregs; // regs restored to initial value
	bool saved; // state was saved to internal stack
	bool restored; // state was restored from internal stack

	bool isReturnLocation() const
	{
		if (!imgloc)
			return false;
		byte opcode = *imgloc;
		if (opcode == 0xf3) // rep prefix for the AMD fix (http://repzret.org/p/repzret/)
			opcode = *(imgloc + 1);
		if (opcode == 0xc2 || opcode == 0xc3 ||	// near return
			opcode == 0xca || opcode == 0xcb)	// far return
			return true;
		return false;
	}
};

class CFACursor
{
public:
	CFACursor(const PEImage& img_, const CompilationUnitData& cu_, const CFIEntry& cfientry,
		const CFICursor& cficursor_, unsigned long long location)
		: img(img_), cu(cu_), entry(cfientry), cficursor(cficursor_)
	{
		initial.loc = location;
		initial.imgloc = img.RVA<byte>((unsigned long)(initial.loc - img.getImageBase()), 1);
		initial.cfa = mkCFARel(0);
		initial.saved = false;
		initial.restored = false;
		initial.returnreg = entry.return_address_register;
		setInstructions(entry.initial_instructions, entry.initial_instructions_length, true);
	}

	void setInstructions(byte* instructions, int length, bool initial = false)
	{
		beg = instructions;
		end = instructions + length;
		ptr = beg;
		evalinit = initial;
		if (!initial)
			current = this->initial;
	}

	bool beforeRestore() const
	{
		if (ptr >= end)
			return false;
		byte instr = *ptr;
		if ((instr & 0xc0) == DW_CFA_restore || instr == DW_CFA_restore_extended ||
			instr == DW_CFA_restore_state)
			return true;
		return false;
	}

	bool beforeLocationChange() const
	{
		if (ptr >= end)
			return false;
		byte instr = *ptr;
		if ((instr & 0xc0) == DW_CFA_advance_loc ||
			(instr >= DW_CFA_set_loc && instr <= DW_CFA_advance_loc4))
			return true;
		return false;
	}

	bool processNext()
	{
		if (ptr >= end)
			return false;
		byte instr = *ptr++;
		int reg;
		int delta;
		CFAState& state = evalinit ? initial : current;
#define restoreReg(reg) \
		do { \
			auto regruleit = initial.savedregs.find(reg); \
			if (regruleit != initial.savedregs.end()) \
				current.savedregs[reg] = regruleit->second; \
			else \
				current.savedregs.erase(reg); \
			current.restoredregs.push_back(reg); \
		} while (0) \

#define advanceLoc(delta) \
		do { \
			state.loc += delta; \
			state.imgloc += delta; \
			state.restoredregs.clear(); \
		} while (0) \

		switch (instr & 0xc0)
		{
		case DW_CFA_advance_loc:
			delta = (instr & 0x3f) * entry.code_alignment_factor;
			advanceLoc(delta);
			break;
		case DW_CFA_offset: // set register rule to "factored offset"
			state.savedregs[instr & 0x3f] = mkDerefCFARel(LEB128<unsigned long long>(ptr) * entry.data_alignment_factor, img.isX64());
			break;
		case DW_CFA_restore:
			assert(!evalinit);
			reg = instr & 0x3f; // restore register to initial state
			restoreReg(reg);
			break;

		case DW_CFA_extended:
			switch (instr)
			{
			case DW_CFA_set_loc:
				state.loc = cficursor.readEncodedValue(ptr, entry.fde_encoding, entry.address_size, entry.initial_location);
				state.imgloc = img.RVA<byte>((unsigned long)(state.loc - img.getImageBase()), 1);
				state.restoredregs.clear();
				break;
			case DW_CFA_advance_loc1:
				delta = (*ptr++) * entry.code_alignment_factor;
				advanceLoc(delta);
				break;
			case DW_CFA_advance_loc2:
				delta = RD2(ptr) * entry.code_alignment_factor;
				advanceLoc(delta);
				break;
			case DW_CFA_advance_loc4:
				delta = RD4(ptr) * entry.code_alignment_factor;
				advanceLoc(delta);
				break;

			case DW_CFA_def_cfa:
				state.cfa.reg = LEB128<unsigned>(ptr);
				state.cfa.off = LEB128<unsigned long long>(ptr);
				break;
			case DW_CFA_def_cfa_sf:
				state.cfa.reg = LEB128<unsigned>(ptr);
				state.cfa.off = SLEB128<long long>(ptr) * entry.data_alignment_factor;
				break;
			case DW_CFA_def_cfa_register:
				state.cfa.reg = LEB128<unsigned>(ptr);
				break;
			case DW_CFA_def_cfa_offset:
				state.cfa.off = LEB128<unsigned long long>(ptr);
				break;
			case DW_CFA_def_cfa_offset_sf:
				state.cfa.off = SLEB128<long long>(ptr) * entry.data_alignment_factor;
				break;
			case DW_CFA_def_cfa_expression:
			{
				DWARF_Attribute attr;
				attr.type = ExprLoc;
				attr.expr.len = LEB128<unsigned long long>(ptr);
				attr.expr.ptr = ptr;
				state.cfa = decodeLocation(attr, cu);
				ptr += attr.expr.len;
				break;
			}

			case DW_CFA_undefined:
				reg = LEB128<unsigned>(ptr); // set register rule to "undefined"
				current.savedregs.erase(reg);
				break;
			case DW_CFA_same_value:
				reg = LEB128<unsigned>(ptr); // set register rule to "same value"
				// no modification
				break;
			case DW_CFA_offset_extended:
				reg = LEB128<unsigned>(ptr); // set register rule to "factored offset"
				state.savedregs[reg] = mkDerefCFARel(LEB128<unsigned long long>(ptr) * entry.data_alignment_factor, img.isX64());
				break;
			case DW_CFA_offset_extended_sf:
				reg = LEB128<unsigned>(ptr); // set register rule to "factored offset"
				state.savedregs[reg] = mkDerefCFARel(SLEB128<long long>(ptr) * entry.data_alignment_factor, img.isX64());
				break;
			case DW_CFA_val_offset:
				reg = LEB128<unsigned>(ptr); // set register rule to "val offset"
				state.savedregs[reg] = mkCFARel(LEB128<unsigned long long>(ptr) * entry.data_alignment_factor);
				break;
			case DW_CFA_val_offset_sf:
				reg = LEB128<unsigned>(ptr); // set register rule to "val offset"
				state.savedregs[reg] = mkCFARel(SLEB128<long long>(ptr) * entry.data_alignment_factor);
				break;
			case DW_CFA_register:
				reg = LEB128<unsigned>(ptr); // set register rule to "register"
				state.savedregs[reg] = mkInReg(LEB128<unsigned>(ptr));
				break;
			case DW_CFA_expression:
			case DW_CFA_val_expression:
			{
				reg = LEB128<unsigned>(ptr); // set register rule to "expression"
				DWARF_Attribute attr;
				attr.type = ExprLoc;
				attr.expr.len = LEB128<unsigned long long>(ptr);
				attr.expr.ptr = ptr;
				Location loc = decodeLocation(attr, cu);
				if (instr == DW_CFA_expression) // differentiate between value and location
				{
					assert((loc.type & Location::Deref) == 0);
					loc.type |= Location::Deref;
					loc.valoff = 0;
					loc.refsize = img.isX64() ? 8 : 4; // source reg size
				}
				state.savedregs[reg] = loc;
				ptr += attr.expr.len;
				break;
			}
			case DW_CFA_restore_extended:
				assert(!evalinit);
				reg = LEB128<unsigned>(ptr); // restore register to initial state
				restoreReg(reg);
				break;

			case DW_CFA_remember_state:
				stack.push_back(state);
				state.saved = true; // need to be reset outside
				break;
			case DW_CFA_restore_state:
			{
				if (stack.empty())
					assert(false);
				unsigned long long loc = state.loc;
				byte* imgloc = state.imgloc;
				state = stack.back();
				stack.pop_back();
				state.loc = loc;
				state.imgloc = imgloc;
				state.restored = true; // need to be reset outside
				break;
			}

			case DW_CFA_GNU_window_save:
			{
				int size = 4; // source reg size
				for (reg = 8; reg < 16; reg++)
					state.savedregs[reg] = mkInReg(reg + 16);
				for (reg = 16; reg < 32; reg++)
					state.savedregs[reg] = mkDerefCFARel((reg - 16) * size, img.isX64());
				break;
			}
			case DW_CFA_GNU_negative_offset_extended:
				reg = LEB128<unsigned>(ptr); // set register rule to negative "factored offset"
				state.savedregs[reg] = mkDerefCFARel(-(long long)(LEB128<unsigned long long>(ptr) * entry.data_alignment_factor), img.isX64());
				break;

			case DW_CFA_GNU_args_size:
				LEB128<unsigned long long>(ptr); // ignore
				break;
			case DW_CFA_nop:
				break;
			default:
				assert(false);
			}
		}
		return true;
	}

	const CompilationUnitData& cu;
	const PEImage& img;
	const CFIEntry& entry;
	const CFICursor& cficursor;
	byte* beg;
	byte* end;
	byte* ptr;

	bool evalinit;
	CFAState initial;
	CFAState current;
	std::vector<CFAState> stack;
};

static std::vector<CFAState> getCFAStatesForRange(const PEImage& img, const PEImage& dbgimg, const CompilationUnitData& cu, pcRange_t range)
{
	std::vector<CFAState> result;
	if (!dbgimg.debug_frame && !img.eh_frame)
		return result;

	static bool rounds[] = { true, false };
	for (size_t i = img.eh_frame_length ? 0 : 1; i < ARRAYSIZE(rounds); i++)
	{
		CFIEntry entry;
		CFICursor cursor(img, dbgimg, rounds[i]);
		while (cursor.readNext(entry))
		{
			if (entry.type == CFIEntry::FDE &&
				entry.initial_location <= range.pclo && entry.initial_location + entry.address_range >= range.pchi)
			{
				CFACursor cfa(img, cu, entry, cursor, entry.initial_location);
				while (cfa.processNext()) {}
				cfa.setInstructions(entry.instructions, entry.instructions_length);
				do {
					if (cfa.beforeLocationChange() || cfa.current.saved || cfa.current.restored)
					{
						result.push_back(cfa.current);
						if (cfa.current.saved || cfa.current.restored)
							cfa.current.saved = cfa.current.restored = false;
					}
				} while (cfa.processNext());
				result.push_back(cfa.current);
				return result;
			}
		}
	}
	return result;
}

static std::set<unsigned long long> getCFAChangeLocations(const std::vector<CFAState>& states)
{
	std::set<unsigned long long> result;
	const Location* lastcfa = NULL;
	for (const CFAState& state : states)
	{
		if (!lastcfa || *lastcfa != state.cfa)
		{
			result.insert(state.loc);
			lastcfa = &state.cfa;
		}
	}
	return result;
}

static const CFAState* findBestCFA(const PEImage& img, const std::vector<CFAState>& states, pcRange_t range)
{
	if (states.empty() || range.pchi <= range.pclo)
		return NULL;

	size_t i;
	for (i = 0; i < states.size(); i++)
	{
		const auto& state = states[i];
		if (state.loc >= range.pclo)
			break;
	}

	if (i == states.size())
		return &states[i - 1]; // return last state for ranges after this state

	const CFAState* laststate = NULL;
	for (; i < states.size() - 1; i++)
	{
		const CFAState& state = states[i];
		const CFAState& nextstate = states[i + 1];

		if (laststate != NULL && state.loc >= range.pchi)
			return laststate; // return last in-range state

		// terminate at least on return op
		if (state.isReturnLocation())
			return &state;

		// terminate once before first restore is done
		if (!nextstate.restoredregs.empty())
		{
			if (laststate == NULL || laststate->cfa.reg != state.cfa.reg ||
				laststate->cfa.off <= state.cfa.off)
				return &state; // return state for restore op
			return laststate; // return state before the restore op was reached
		}

		laststate = &state;
	}

	if (laststate != NULL && states[i].loc >= range.pchi)
		return laststate; // return last in-range state

	return &states[i];
}

static Location findBestFBLoc(const PEImage& img, const CompilationUnitData& cu, unsigned long long fblocoff)
{
	int regebp = img.isX64() ? dwarf_reg64_rbp : dwarf_reg32_ebp;
	LOCCursor cursor(cu, (byte*)img.debug_loc, img.debug_loc_length, fblocoff);
	LOCEntry entry;
	Location longest = mkCFARel(0);
	unsigned long long longest_range = 0;
	while (cursor.readNext(entry))
	{
		Location loc = decodeLocation(entry.attr, cu);
		if (loc.is_regrel() && loc.reg == regebp)
			return loc;
		unsigned long long range = entry.end_offset - entry.beg_offset;
		if (range > longest_range)
		{
			longest_range = range;
			longest = loc;
		}
	}
	return longest;
}

unsigned short CV2PDB::appendStackVar(const char* name, int type, const Location& loc, const Location& cfa)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);

	int reg = loc.reg;
	long long off = loc.off;
	CV_X86_REG baseReg;
	if (reg == DW_REG_CFA)
	{
		reg = cfa.reg;
		off += cfa.off;
	}
	assert(off <= LONG_MAX || off >= LONG_MIN);
	if (img.isX64())
		baseReg = dwarf_to_amd64_reg(reg);
	else
		baseReg = dwarf_to_x86_reg(reg);

	if (baseReg == CV_REG_NONE)
		return baseReg;

	if (baseReg == CV_REG_EBP)
	{
		cvs->stack_v2.id = v3 ? S_BPREL_V3 : S_BPREL_V2;
		cvs->stack_v2.offset = (int)off;
		cvs->stack_v2.symtype = type;
		len = cstrcpy_v(v3, (BYTE*)&cvs->stack_v2.p_name, name);
		len += (BYTE*)&cvs->stack_v2.p_name - (BYTE*)cvs;
	}
	else
	{
		cvs->regrel_v3.id = S_REGREL_V3;
		cvs->regrel_v3.reg = baseReg;
		cvs->regrel_v3.offset = (int)off;
		cvs->regrel_v3.symtype = type;
		len = cstrcpy_v(true, (BYTE*)cvs->regrel_v3.name, name);
		len += (BYTE*)&cvs->regrel_v3.name - (BYTE*)cvs;
	}
	for (; len & (align - 1); len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	cvs->stack_v2.len = len - 2;
	cbModSymbols += len;
	return baseReg;
}

unsigned short CV2PDB::appendRegVar(const char* name, int type, const Location& loc, const Location& cfa)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);

	int reg = loc.reg;
	CV_X86_REG baseReg;
	if (reg == DW_REG_CFA)
	{
		reg = cfa.reg;
	}
	if (img.isX64())
		baseReg = dwarf_to_amd64_reg(reg);
	else
		baseReg = dwarf_to_x86_reg(reg);

	if (baseReg == CV_REG_NONE)
		return baseReg;

	cvs->register_v2.id = v3 ? S_REGISTER_V3 : S_REGISTER_V2;
	cvs->register_v2.reg = baseReg;
	cvs->register_v2.type = type;
	len = cstrcpy_v(v3, (BYTE*)&cvs->register_v2.p_name, name);
	len += (BYTE*)&cvs->register_v2.p_name - (BYTE*)cvs;

	for (; len & (align - 1); len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	cvs->register_v2.len = len - 2;
	cbModSymbols += len;
	return baseReg;
}

void CV2PDB::appendLocalVar(const char* name, int type, bool isparam)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
	cvs->local_v2.id = v3 ? S_LOCAL_V3 : S_LOCAL_V2;
	cvs->local_v2.type = type;
	cvs->local_v2.flags = isparam ? CV_LVARFLAGS_fIsParam : 0;
	len = cstrcpy_v(v3, (BYTE*)&cvs->local_v2.p_name, name);
	len += (BYTE*)&cvs->local_v2.p_name - (BYTE*)cvs;

	for (; len & (align - 1); len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	cvs->local_v2.len = len - 2;
	cbModSymbols += len;
}

void CV2PDB::appendGlobalVar(const char* name, int type, int seg, int offset)
{
	unsigned int len;
	const unsigned int align = 4;

	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
	cvs->data_v2.id = v3 ? S_GDATA_V3 : S_GDATA_V2;
	cvs->data_v2.offset = offset;
	cvs->data_v2.symtype = type;
	cvs->data_v2.segment = seg;
	len = cstrcpy_v(v3, (BYTE*)&cvs->data_v2.p_name, name);
	len += (BYTE*)&cvs->data_v2.p_name - (BYTE*)cvs;
	for (; len & (align - 1); len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	cvs->data_v2.len = len - 2;
	cbModSymbols += len;
}

unsigned short CV2PDB::appendRangeStack(pcRange_t range, const std::vector<pcRange_t>& gaps, const Location& loc, const Location& cfa, bool fullscope)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc(sizeof(codeview_symbol::range_regrel_v3) + (gaps.size() * sizeof(CV_LVAR_ADDR_GAP)));

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);

	int reg = loc.reg;
	long long off = loc.off;
	CV_X86_REG baseReg;
	if (reg == DW_REG_CFA)
	{
		reg = cfa.reg;
		off += cfa.off;
	}
	assert(off <= LONG_MAX || off >= LONG_MIN);
	if (img.isX64())
		baseReg = dwarf_to_amd64_reg(reg);
	else
		baseReg = dwarf_to_x86_reg(reg);

	if (baseReg == CV_REG_NONE)
		return baseReg;

	assert(!fullscope || gaps.empty());
	if (baseReg == CV_REG_EBP)
	{
		cvs->range_stack_v3.id = fullscope ? S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE_V3 : S_DEFRANGE_FRAMEPOINTER_REL_V3;
		cvs->range_stack_v3.offFramePointer = (long)off;
		if (!fullscope)
		{
			cvs->range_stack_v3.range.offStart = (unsigned long)(range.pclo - codeSegOff);
			cvs->range_stack_v3.range.isectStart = img.codeSegment + 1;
			cvs->range_stack_v3.range.cbRange = (unsigned short)(range.pchi - range.pclo);
			len = sizeof(cvs->range_stack_v3);
		}
		else
			len = sizeof(cvs->range_stack_fullscope_v3);
	}
	else
	{
		cvs->range_regrel_v3.id = S_DEFRANGE_REGISTER_REL_V3;
		cvs->range_regrel_v3.baseReg = baseReg;
		cvs->range_regrel_v3.offsetParent = 0 << 4 | 0;
		cvs->range_regrel_v3.offBasePointer = (long)off;
		cvs->range_regrel_v3.range.offStart = (unsigned long)(range.pclo - codeSegOff);
		cvs->range_regrel_v3.range.isectStart = img.codeSegment + 1;
		cvs->range_regrel_v3.range.cbRange = (unsigned short)(range.pchi - range.pclo);
		len = sizeof(cvs->range_regrel_v3);
	}
	CV_LVAR_ADDR_GAP* cvgap = (CV_LVAR_ADDR_GAP*)((byte*)cvs + len);
	if (!fullscope)
	{
		for (const auto& gap : gaps)
		{
			if ((gap.pclo - range.pclo) > USHRT_MAX)
			{
				assert(false);
				continue;
			}
			cvgap->gapStartOffset = (unsigned short)(gap.pclo - range.pclo);
			cvgap->cbRange = (unsigned short)(gap.pchi - gap.pclo);
			cvgap++;
		}
	}
	len = (byte*)cvgap - (byte*)cvs; //(gaps.size() * sizeof(CV_LVAR_ADDR_GAP)) + sizeof(cvs->range_register_v3);
	cvs->stack_v2.len = len - 2;
	cbModSymbols += len;
	return baseReg;
}

unsigned short CV2PDB::appendRangeReg(pcRange_t range, const std::vector<pcRange_t>& gaps, const Location& loc, const Location& cfa)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc((gaps.size() * sizeof(CV_LVAR_ADDR_GAP)) + sizeof(codeview_symbol::range_register_v3));

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);

	int reg = loc.reg;
	CV_X86_REG baseReg;
	if (reg == DW_REG_CFA)
	{
		reg = cfa.reg;
	}
	if (img.isX64())
		baseReg = dwarf_to_amd64_reg(reg);
	else
		baseReg = dwarf_to_x86_reg(reg);

	if (baseReg == CV_REG_NONE)
		return baseReg;


	cvs->range_register_v3.id = S_DEFRANGE_REGISTER_V3;
	cvs->range_register_v3.reg = baseReg;
	cvs->range_register_v3.attr = 0;
	cvs->range_register_v3.range.offStart = (unsigned long)(range.pclo - codeSegOff);
	cvs->range_register_v3.range.isectStart = img.codeSegment + 1;
	cvs->range_register_v3.range.cbRange = (unsigned short)(range.pchi - range.pclo);
	CV_LVAR_ADDR_GAP* cvgap = (CV_LVAR_ADDR_GAP*)((byte*)cvs + sizeof(cvs->range_register_v3));
	for (const auto& gap : gaps)
	{
		if ((gap.pclo - range.pclo) > USHRT_MAX)
		{
			assert(false);
			continue;
		}
		cvgap->gapStartOffset = (unsigned short)(gap.pclo - range.pclo);
		cvgap->cbRange = (unsigned short)(gap.pchi - gap.pclo);
		cvgap++;
	}
	len = (byte*)cvgap - (byte*)cvs; //(gaps.size() * sizeof(CV_LVAR_ADDR_GAP)) + sizeof(cvs->range_register_v3);

	cvs->range_register_v3.len = len - 2;
	cbModSymbols += len;
	return baseReg;
}

void CV2PDB::appendRangeProg(pcRange_t range, const std::vector<pcRange_t>& gaps, int prog)
{
	unsigned int len;
	const unsigned int align = 4;
	checkModSymbolAlloc((gaps.size() * sizeof(CV_LVAR_ADDR_GAP)) + sizeof(codeview_symbol::range_v3));

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);

	cvs->range_v3.id = S_DEFRANGE_V3;
	cvs->range_v3.program = prog;
	cvs->range_v3.range.offStart = (unsigned long)(range.pclo - codeSegOff);
	cvs->range_v3.range.isectStart = img.codeSegment + 1;
	cvs->range_v3.range.cbRange = (unsigned short)(range.pchi - range.pclo);
	CV_LVAR_ADDR_GAP* cvgap = (CV_LVAR_ADDR_GAP*)((byte*)cvs + sizeof(cvs->range_v3));
	for (const auto& gap : gaps)
	{
		if ((gap.pclo - range.pclo) > USHRT_MAX)
		{
			assert(false);
			continue;
		}
		cvgap->gapStartOffset = (unsigned short)(gap.pclo - range.pclo);
		cvgap->cbRange = (unsigned short)(gap.pchi - gap.pclo);
		cvgap++;
	}
	len = (byte*)cvgap - (byte*)cvs; //(gaps.size() * sizeof(CV_LVAR_ADDR_GAP)) + sizeof(cvs->range_v3);

	cvs->range_register_v3.len = len - 2;
	cbModSymbols += len;
}

void CV2PDB::appendEndArg()
{
	checkModSymbolAlloc(8);

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
	cvs->generic.id = S_ENDARG_V1;
	cvs->generic.len = 2;
	cbModSymbols += 4;
}

void CV2PDB::appendEnd(int offStart)
{
	checkModSymbolAlloc(8);

	codeview_symbol*start = (codeview_symbol*)(modSymbols + offStart);
	start->generic_block.pend = cbModSymbols;

	codeview_symbol*cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
	cvs->generic.id = S_END_V1;
	cvs->generic.len = 2;
	cbModSymbols += 4;
}

int CV2PDB::appendLexicalBlock(const pcRange_t& range, int offParent)
{
	checkModSymbolAlloc(32);

	codeview_symbol*dsym = (codeview_symbol*)(modSymbols + cbModSymbols);
	dsym->block_v3.id = S_BLOCK_V3;
	dsym->block_v3.parent = offParent;
	dsym->block_v3.end = 0; // set by appendEnd(dsym) // destSize + sizeof(dsym->block_v3) + 12;
	dsym->block_v3.length = (unsigned long)(range.pchi - range.pclo);
	dsym->block_v3.offset = (unsigned long)(range.pclo - codeSegOff);
	dsym->block_v3.segment = img.codeSegment + 1;
	dsym->block_v3.name[0] = 0;
	int len = sizeof(dsym->block_v3);
	for (; len & 3; len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	dsym->block_v3.len = len - 2;
	cbModSymbols += len;
	return len;
}

void CV2PDB::appendLabel(const char* name, unsigned long long pc)
{
	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*dsym = (codeview_symbol*)(modSymbols + cbModSymbols);
	dsym->label_v1.id = v3 ? S_LABEL_V3 : S_LABEL_V1;
	dsym->label_v1.offset = (unsigned long)(pc - codeSegOff);
	dsym->label_v1.segment = img.codeSegment + 1;
	dsym->label_v1.flags = 0; // CV_PFLAG_NOTREACHED;
	int len = cstrcpy_v(v3, (BYTE*)&dsym->label_v1.p_name, name);
	len += (BYTE*)&dsym->label_v1.p_name - (BYTE*)dsym;

	for (; len & 3; len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	dsym->label_v1.len = len - 2;
	cbModSymbols += len;
}

int CV2PDB::appendThunk(const char * name, const pcRange_t & range)
{
	checkModSymbolAlloc(100 + kMaxNameLen);

	codeview_symbol*dsym = (codeview_symbol*)(modSymbols + cbModSymbols);
	dsym->thunk_v1.id = v3 ? S_THUNK_V3 : S_THUNK_V1;
	dsym->thunk_v1.pparent = 0;
	dsym->thunk_v1.pend = 0; // set by appendEnd(dsym) // destSize + sizeof(dsym->block_v3) + 12;
	dsym->thunk_v1.next = 0;
	assert((range.pchi - range.pclo) < USHRT_MAX);
	dsym->thunk_v1.thunk_len = (unsigned short)(range.pchi - range.pclo);
	dsym->thunk_v1.offset = (unsigned long)(range.pclo - codeSegOff);
	dsym->thunk_v1.segment = img.codeSegment + 1;
	dsym->thunk_v1.thtype = THUNK_ORDINAL_NOTYPE;
	int len = cstrcpy_v(v3, (BYTE*)&dsym->thunk_v1.p_name, name);
	len += (BYTE*)&dsym->thunk_v1.p_name - (BYTE*)dsym;
	for (; len & 3; len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	dsym->block_v3.len = len - 2;
	cbModSymbols += len;
	return len;
}

void CV2PDB::appendFPOData(const PDB_FPO_DATA& fpo_data)
{
	checkModFPODataAlloc(sizeof(PDB_FPO_DATA));
	PDB_FPO_DATA* data = (PDB_FPO_DATA*)(modFPOData + cbModFPOData);
	*data = fpo_data;
	cbModFPOData += sizeof(PDB_FPO_DATA);
}

int CV2PDB::appendString(const char* str)
{
	checkModStringTableAlloc(kMaxNameLen);
	int off = cbModStringTable;
	int len = cstrcpy_v(v3, modStringTable + cbModStringTable, str, false);
	cbModStringTable += len;
	return off;
}

bool CV2PDB::getDWARFSubroutineParameters(DWARF_InfoData& procid, const CompilationUnitData& cu, DIECursor cursor, std::vector<DWARF_Parameter>* params)
{
	DWARF_InfoData id;
	DWARF_Parameter param;
	param.is_varargs = false;
	bool has_this = false;
	int iparam = 0;

	/* Count the number of parameters.
	FIXME: GDB currently ignores vararg functions, but knows about
	vararg member functions.  */
	while (cursor.readNext(id) && id.tag)
	{
		if (!param.is_varargs)
		{
			if (id.tag == DW_TAG_formal_parameter)
			{
				param.name = id.name;
				param.type = id.type;
				//TODO: evaluate default value
				//param.default_value = id.default_value;
				param.is_this = false;

				/* DWARF version 2 has no clean way to discern C++
				static and non-static member functions.  G++ helps
				GDB by marking the first parameter for non-static
				member functions (which is the this pointer) as
				artificial.  We pass this information to
				dwarf2_add_member_fn via TYPE_FIELD_ARTIFICIAL.

				DWARF version 3 added DW_AT_object_pointer, which GCC
				4.5 does not yet generate.  */
				bool artific = id.artificial;
				if (!artific)
				{
					/* GCC/43521: In java, the formal parameter
					"this" is sometimes not marked with DW_AT_artificial.  */
					if (cu.language == CompilationUnitData::language_java)
					{
						if (param.name && !strcmp(param.name, "this"))
							param.is_this = true;
					}
				}
				else
				{
					if (procid.object_pointer)
					{
						/* If the compiler emits this, use it.  */
						if (procid.object_pointer == id.entryPtr)
							param.is_this = true;
					}
					else if (param.name && strcmp(param.name, "this") == 0)
						/* Function definitions will have the argument names.  */
						param.is_this = true;
					else if (param.name == NULL && iparam == 0)
						/* Declarations may not have the names, so like
						elsewhere in GDB, assume an artificial first
						argument is "this".  */
						param.is_this = true;
				}

				if (param.is_this)
				{
					has_this = true;
					if (!params)
						break;
				}
				if (params)
					params->push_back(param);
				iparam++;
			}
			else if (id.tag == DW_TAG_unspecified_parameters)
			{
				param.name = NULL;
				param.type = NULL;
				param.is_this = false;
				param.is_varargs = true;
				if (params)
					params->push_back(param);
				iparam++;
			}
		}
		else if (id.tag == DW_TAG_formal_parameter ||
			id.tag == DW_TAG_unspecified_parameters)
		{
			assert(false); // must be the last parameter
			break;
		}
		cursor.gotoSibling();
	}

	return has_this;
}

int CV2PDB::addDWARFSubroutineType(DWARF_InfoData& procid, const CompilationUnitData& cu, DIECursor cursor, int class_type, bool inlined)
{
	// append subroutine type info
	codeview_reftype* rtype;
	codeview_type* ftype;
	int return_type = getTypeByDWARFPtr(cu, procid.type);

	//TODO: do something usefull with this info
	bool prototyped = procid.prototyped;
	bool noreturn = procid.noreturn;
	bool deleted = procid.deleted;
	unsigned char callconv = 0;
	if (inlined)
		callconv = CV_CALL_INLINE;
	else if (procid.calling_convention)
		callconv = dwarf_to_cv_callconv(procid.calling_convention);
	//else if (cu.producer && strstr(cu.producer, "IBM XL C for OpenCL"))
	//	callconv = DW_CC_GDB_IBM_OpenCL;
	else
	{
		switch (cu.language)
		{
		case CompilationUnitData::language_c:
		case CompilationUnitData::language_cplus:
		case CompilationUnitData::language_go:
			callconv = CV_CALL_NEAR_C;
			break;
		default:
			callconv = CV_CALL_NEAR_STD;
			break;
		}
	}

	// arglist
	int void_type = T_VOID; // void
	int nparams, iparams;
	bool varargs = false;
	bool memberfn = class_type != 0;

	bool has_this;
	std::vector<DWARF_Parameter> params;
	has_this = getDWARFSubroutineParameters(procid, cu, cursor, &params);
	nparams = params.size() - (has_this ? 1 : 0);
	if (has_this)
	{
		callconv = CV_CALL_THISCALL;
		memberfn = true;
	}

	int this_type = T_NOTYPE;
	int arglistType;
	checkUserTypeAlloc();
	int funcType = nextUserType++;

	if (nparams)
	{
		checkDWARFTypeAlloc(100);
		rtype = (codeview_reftype*)(dwarfTypes + cbDwarfTypes);
		rtype->arglist_v2.id = LF_ARGLIST_V2;
		rtype->arglist_v2.len = (unsigned short)(offsetof(codeview_reftype, arglist_v2.args) - 2 +
			(nparams * sizeof(rtype->arglist_v2.args[0])));
		rtype->arglist_v2.num = nparams;
		cbDwarfTypes += rtype->arglist_v2.len + 2;
		arglistType = nextDwarfType++;

		/* Allocate storage for parameters and fill them in.  */
		unsigned* args = (unsigned*)rtype->arglist_v2.args;

		/* TYPE_FIELD_TYPE must never be NULL.  Pre-fill the array to ensure it
		even if we error out during the parameters reading below.  */
		for (iparams = 0; iparams < nparams; iparams++)
			args[iparams] = void_type;

		iparams = 0;
		for (const auto& param : params)
		{
			if (!param.is_varargs)
			{
				int arg_type;
				int arg_type_mods;

				arg_type = getTypeByDWARFPtr(cu, param.type);

				if (param.is_this)
				{
					if (arg_type == funcType)
						arg_type_mods = 0; // func types don't have modifiers to start with
					else if (arg_type > funcType)
						arg_type_mods = getDWARFTypeCVModifier(param.type, true);
					else
						arg_type_mods = getTypeModifier(arg_type, true);
					/* RealView does not mark THIS as const, which the testsuite
					expects.  GCC marks THIS as const in method definitions,
					but not in the class specifications (GCC PR 43053).  */
					if (cu.language == CompilationUnitData::language_cplus && !(arg_type_mods&CV_modifier_const))
					{
						bool newtype = true;
						codeview_type* cvtype_arg;
						if (arg_type < funcType)
						{
							//HACK: use const cast here, so other code don't need to be modified for constness,
							// but we know it's safe to cast
							cvtype_arg = const_cast<codeview_type*>(getTypeData(arg_type));
							if (cvtype_arg->generic.id == LF_MODIFIER_V2)
							{
								cvtype_arg->modifier_v2.attribute |= CV_modifier_const;
								newtype = false;
							}
							else if (cvtype_arg->generic.id == LF_POINTER_V2)
							{
								cvtype_arg->pointer_v2.attribute |= CV_PTR_isconst;
								newtype = false;
							}
						}
						if (newtype)
						{
							cvtype_arg = (codeview_type*)(dwarfTypes + cbDwarfTypes);
							cbDwarfTypes += addModifierType(cvtype_arg, arg_type, CV_modifier_const);
							arg_type = nextDwarfType++;
						}
					}
					this_type = arg_type;

					continue;
				}

				args[iparams] = arg_type;
				iparams++;
			}
			else
			{
				args[iparams] = T_NOTYPE; // type for var arg parameter
				iparams++;
			}
		}
	}
	else
	{
		arglistType = createEmptyArgListType();
	}

	// func type
	ftype = (codeview_type*)(userTypes + cbUserTypes);
	if (memberfn)
	{
		ftype->mfunction_v2.id = LF_MFUNCTION_V2;
		ftype->mfunction_v2.len = sizeof(ftype->mfunction_v2) - 2;
		ftype->mfunction_v2.rvtype = return_type;
		ftype->mfunction_v2.class_type = class_type; //TODO: get actual class type
		ftype->mfunction_v2.this_type = this_type;
		ftype->mfunction_v2.call = callconv;
		ftype->mfunction_v2.attr = 0; // CV_funcattr_ctor | ...
		ftype->mfunction_v2.params = nparams;
		ftype->mfunction_v2.arglist = arglistType;
		ftype->mfunction_v2.this_adjust = 0; //TODO: ...
	}
	else
	{
		ftype->procedure_v2.id = LF_PROCEDURE_V2;
		ftype->procedure_v2.len = sizeof(ftype->procedure_v2) - 2;
		ftype->procedure_v2.rvtype = return_type;
		ftype->procedure_v2.call = callconv;
		ftype->procedure_v2.attr = 0; // CV_funcattr_ctor | ...
		ftype->procedure_v2.params = nparams;
		ftype->procedure_v2.arglist = arglistType;
	}
	cbUserTypes += ftype->generic.len + 2;

	return funcType;
}

__inline static FrameInfoData& getNewPrevFrame(FrameInfoData& frame, std::vector<FrameInfoData>& framelist)
{
	framelist.push_back(frame);
	size_t count = framelist.size();
	for (size_t i = 0; i < count; i++)
	{
		FrameInfoData& outer = framelist[i];
		FrameInfoData& inner = i < (count - 1) ? framelist[i + 1] : frame;
		outer.next = &inner;
		inner.prev = &outer;
		if (i == (count - 1))
			return outer;
	}
	__assume(false);
}

__inline static bool findBlockVarInfo(const blockMap_t& blockVars, byte* die_ptr)
{
	for (const auto& parentblock : blockVars)
	{
		for (const auto& childblock : parentblock.second.map)
		{
			for (const auto& var : childblock.second.map)
			{
				if (die_ptr == var.second.die_ptr)
					return true;
			}
		}
	}
	return false;
}

static void addBlockVarLocation(rangeVarMapValue_t& varEntry, const blockMap_t& blockVars, const std::set<unsigned long long>& cfaChangeLocs, const pcRange_t& liveRange, const Location& loc)
{
	if (varEntry.die_ptr)
	{
		if (loc.is_implptr() && loc.die_ptr == varEntry.die_ptr)
			assert(false);
	}
	if (!loc.is_implptr() || !findBlockVarInfo(blockVars, loc.die_ptr))
	{
		std::set<pcRange_t>& ranges = varEntry.map[loc];
		if ((loc.is_inreg() || loc.is_regrel()) && loc.reg == DW_REG_CFA)
		{
			pcRange_t range = liveRange;
			for (auto changeit = cfaChangeLocs.upper_bound(liveRange.pclo);
				changeit != cfaChangeLocs.end() && *changeit < liveRange.pchi; ++changeit)
			{
				range.pchi = *changeit;
				ranges.insert(range);
				range.pclo = range.pchi;
			}
			if (ranges.empty() || range.pchi < liveRange.pchi)
			{
				if (range.pchi < liveRange.pchi)
					range.pchi = liveRange.pchi;
				ranges.insert(range);
			}
		}
		else
		{
			ranges.insert(liveRange);
		}
	}
}

static inline void appendSavedRegsToFPOProgram(std::ostrstream& prog, unsigned reg, const Location& savedloc, const Location* savedebp, bool isX64)
{
	const int ebp = isX64 ? dwarf_reg64_rbp : dwarf_reg32_ebp;
	const int esp = isX64 ? dwarf_reg64_rsp : dwarf_reg32_esp;
	prog << " $" << dwarf_reg_to_fpo_reg(reg, isX64) << " $";
	Location::Type loctype = savedloc.type & (~Location::Deref);
	assert(loctype == Location::RegRel); //TODO: implement other case
	if (savedloc.reg == DW_REG_CFA)
		prog << (savedebp ? "T1" : "T0");
	else if (savedloc.reg == ebp && savedebp)
		prog << "T0";
	else
		prog << dwarf_reg_to_fpo_reg(savedloc.reg, isX64);

	if (savedloc.off != 0ll)
		prog << " " << std::abs(savedloc.off) << (savedloc.off < 0ll ? " -" : " +");

	if (savedloc.need_deref())
		prog << " ^ =";
	else
		prog << " =";
}

static std::string createFPOProgramForCFAState(const CFAState& cfastate, bool isX64)
{
	assert((cfastate.cfa.type & (~Location::Deref)) == Location::RegRel);
	const int ebp = isX64 ? dwarf_reg64_rbp : dwarf_reg32_ebp;
	const int esp = isX64 ? dwarf_reg64_rsp : dwarf_reg32_esp;
	int eip = cfastate.returnreg;
	char resultbuf[1024];
	std::ostrstream result(resultbuf, sizeof(resultbuf));
	auto it = cfastate.savedregs.find(eip);
	if (it != cfastate.savedregs.end())
	{
		const Location& savedeip = it->second;
		it = cfastate.savedregs.find(ebp);
		const Location* savedebp = NULL;
		if (it != cfastate.savedregs.end())
		{
			savedebp = &it->second;
			Location::Type loctype = savedebp->type & (~Location::Deref);
			assert(loctype == Location::RegRel || loctype == Location::InReg);
			result << "$T0 $" << dwarf_reg_to_fpo_reg(savedebp->reg, isX64) << " = ";
		}

		std::ostrstream cfatemp;
		cfatemp << "$" << (savedebp ? "T1" : "T0") << " $" <<
			(savedebp && savedebp->type == cfastate.cfa.type &&
				savedebp->reg == cfastate.cfa.reg ? "T0" : dwarf_reg_to_fpo_reg(cfastate.cfa.reg, isX64));
		if (cfastate.cfa.off != 0ll)
			cfatemp << " " << std::abs(cfastate.cfa.off) << (cfastate.cfa.off < 0ll ? " -" : " +");
		cfatemp << " ^ =";

		result << cfatemp.rdbuf();
		appendSavedRegsToFPOProgram(result, eip, savedeip, savedebp, isX64);
		if (savedebp)
			appendSavedRegsToFPOProgram(result, ebp, *savedebp, savedebp, isX64);

		if (savedeip.need_deref())
		{
			Location savedesp = mkRegRel(savedeip.reg, savedeip.off + 4);
			appendSavedRegsToFPOProgram(result, esp, savedesp, savedebp, isX64);
		}
		else
		{
			//TODO: how to restore esp if eip was not stored in memory?
			assert(false);
		}

		for (const auto& savedreg : cfastate.savedregs)
		{
			if (savedreg.first != eip && savedreg.first != ebp && savedreg.first != esp)
				appendSavedRegsToFPOProgram(result, savedreg.first, savedreg.second, savedebp, isX64);
		}
	}
	return std::string(result.str(), (size_t)result.pcount());
}

//TODO: find out if this is the right program string for DEFRANGE
static std::string createRangeProgramForVarLocation(const char* varname, const Location& loc, const Location& cfa, bool isX64)
{
	assert(cfa.type == (Location::Deref | Location::RegRel));
	char resultbuf[1024];
	std::ostrstream result(resultbuf, sizeof(resultbuf));
	result << "$T0 $" << dwarf_reg_to_fpo_reg(cfa.reg, isX64);
	if (cfa.off != 0ll)
		result << " " << std::abs(cfa.off) << (cfa.off < 0ll ? " -" : " +");
	result << " ^ = $" << varname << " $T0";
	Location::Type loctype = loc.type & (~Location::Deref);
	assert(loctype == Location::RegRel); //TODO: implement other case
	if (loc.off != 0ll)
		result << " " << std::abs(loc.off) << (loc.off < 0ll ? " -" : " +");
	if (loc.need_deref())
		result << " ^ =";
	else
		result << " =";
	return std::string(result.str(), (size_t)result.pcount());
}

bool CV2PDB::addDWARFProc(mspdb::Mod* mod, DWARF_InfoData& procid, const CompilationUnitData& cu, DIECursor cursor)
{
	unsigned int pclo = (unsigned int)(procid.pclo - codeSegOff);
	unsigned int pchi = (unsigned int)(procid.pchi - codeSegOff);

	unsigned int len;
	const unsigned int align = 4;

	checkModSymbolAlloc(100 + kMaxNameLen);

	// GLOBALPROC
	codeview_symbol*proc_sym = (codeview_symbol*)(modSymbols + cbModSymbols);
	if (procid.external)
		proc_sym->proc_v2.id = v3 ? S_GPROC_V3 : S_GPROC_V2;
	else
		proc_sym->proc_v2.id = v3 ? S_LPROC_V3 : S_LPROC_V2;
	proc_sym->proc_v2.pparent = 0;
	proc_sym->proc_v2.pend = 0; // set with appendEnd(proc_sym)
	proc_sym->proc_v2.next = 0;
	proc_sym->proc_v2.proc_len = pchi - pclo;
	proc_sym->proc_v2.debug_start = pclo - pclo;
	proc_sym->proc_v2.debug_end = pchi - pclo;
	proc_sym->proc_v2.offset = pclo;
	proc_sym->proc_v2.segment = img.codeSegment + 1;
	proc_sym->proc_v2.proctype = getTypeByDWARFPtr(cu, procid.entryPtr, true);
	proc_sym->proc_v2.flags = procid.noreturn ? CV_PFLAG_NEVER : 0;
	proc_sym->proc_v2.flags |= mspdb::vsVersion >= 10 ? CV_PFLAG_OPTDBGINFO : 0;

	//    printf("GlobalPROC %s\n", procid.name);

	len = cstrcpy_v(v3, (BYTE*)&proc_sym->proc_v2.p_name, procid.name);
	len += (BYTE*)&proc_sym->proc_v2.p_name - (BYTE*)proc_sym;
	for (; len & (align - 1); len++)
		modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
	proc_sym->proc_v2.len = len - 2;
	cbModSymbols += len;

#if 0
	addStackVar("local_var", 0x1001, 8);
#endif

	FrameInfoData frame = { FrameInfoData::Normal };
	frame.id.code_addr = procid.pclo;
	frame.func = procid.pclo;
	frame.pc = procid.pclo;
	if (procid.frame_base.type == LocListPtr)
		frame.base = findBestFBLoc(dbgimg, cu, procid.frame_base.sec_off.off);
	else {
		frame.base = decodeLocation(procid.frame_base, cu, 0, DW_AT_frame_base);
		if (frame.base.is_abs()) // pointer into location list in .debug_loc? assume CFA
			frame.base = findBestFBLoc(dbgimg, cu, frame.base.off);
	}

	std::vector<CFAState> cfastates = getCFAStatesForRange(img, dbgimg, cu, { procid.pclo, procid.pchi });
	std::set<unsigned long long> cfachanges = getCFAChangeLocations(cfastates);
	const CFAState* cfa = findBestCFA(dbgimg, cfastates, { procid.pclo, procid.pchi });
	Location ebp = { Location::RegRel, img.isX64() ? 16 : 8, img.isX64() ? dwarf_reg64_rbp : dwarf_reg32_ebp };

	//TODO: find a way to put more debug infos in pdb

	bool hasfp = false;
	if (frame.base.is_regrel() || frame.base.is_inreg()) {
		int reg = frame.base.reg;
		if (reg == DW_REG_CFA)
			reg = cfa ? cfa->cfa.reg : ebp.reg;
		hasfp = (reg == ebp.reg);
		// FPO: http://www.nynaeve.net/?p=91
		if (hasfp)
			proc_sym->proc_v2.flags |= CV_PFLAG_NOFPO;
	}

	if (cu.header)
	{
		bool endarg = false;
		DWARF_InfoData id, idBlock = procid;
		unsigned short baseReg;
		long long lowestFPOffset = 0;

		std::vector<DIECursor> lexicalBlocks;
		lexicalBlocks.push_back(cursor);
		std::vector<int> cvsBlockOffs;
		cvsBlockOffs.push_back(cbModSymbols - len); //proc_sym
		std::vector<DWARF_InfoData> idBlocks;
		idBlocks.push_back(idBlock);
		std::vector<DWARF_InfoData> idSkipBlocks;
		blockMap_t blockVars;
		std::list<std::string> varnames;
		std::vector<FrameInfoData> allFrames;

		// evaluate blocks
		while (!lexicalBlocks.empty())
		{
			cursor = lexicalBlocks.back();
			lexicalBlocks.pop_back();
			if (cursor.hasChild) // if it isn't a new subtree cursor and has childs then
				cursor.gotoSibling(); // skip over them (already evaluated)
			if (!idSkipBlocks.empty() &&
				idSkipBlocks.back().pclo == idBlock.pclo &&
				idSkipBlocks.back().pchi == idBlock.pchi)
				idSkipBlocks.pop_back();
			else
			{
				if (idBlock.tag == DW_TAG_inlined_subroutine)
				{
					frame = allFrames.back();
					allFrames.pop_back();
					frame.next = NULL;
				}
				idBlock = idBlocks.back();
				idBlocks.pop_back();
			}

			while (cursor.readNext(id))
			{
				switch (id.tag)
				{
				case DW_TAG_lexical_block:
					if (id.hasChild)
					{
						if (!id.pchi && id.ranges.type != Invalid)
						{
							pcRange_t bounds;
							if (decodeRanges(id.ranges, &bounds, cu, NULL))
							{
								id.pclo = bounds.pclo;
								id.pchi = bounds.pchi;
							}
						}
						if (id.pclo < id.pchi)
						{
							/* some inlines have their own lexical blocks which spans over
							   the full inlined func, but we already created a block for it,
							   so add this to the skip list. */
							if (idBlock.tag != DW_TAG_inlined_subroutine ||
								id.pclo != idBlock.pclo ||
								id.pchi != idBlock.pchi)
							{
								auto& childmap = blockVars[{ idBlock.pclo, idBlock.pchi }].map;
								childmap.try_emplace({ id.pclo, id.pchi });
								idBlocks.push_back(idBlock);
								idBlock = id;
							}
							else
								idSkipBlocks.push_back(id);

							lexicalBlocks.push_back(cursor);
							cursor = lexicalBlocks.back().getSubtreeCursor(); // use list value as parent
							continue;
						}
					}
					break;

				case DW_TAG_GNU_call_site:
				{
					CallSite* callsite = getCallSiteForPC(id.pclo, false);
					assert(callsite != NULL);
					if (callsite && id.external && id.linkage_name)
					{
						unsigned long long impoff = callsite->getImportTargetAddr();
						if (impoff != -1)
						{
							unsigned long long off = callsite->getTargetAddr();
							if (off != impoff)
							{
								byte* instr = img.RVA<byte>((unsigned long)(off - img.getImageBase()), 1);
								//TODO: check also x64 opcode
								if (instr && instr[0] == 0xff &&
									(instr[1] & 0x3f) == ((4 << 3) | 5))
								{
									//jmp near (jmp far not supported yet)
									if (impoff == *(unsigned long*)(instr + 2))
									{
										int seg = img.findSection(off);
										if (seg == img.codeSegment)
										{
											id.pclo = off;
											id.pchi = off + 6;
											DWARF_InfoData& thunkid = mapImportsToThunks[impoff];
											if (!thunkid.entryPtr)
												thunkid = id;
											else
											{
												assert(thunkid.pclo == off &&
													thunkid.pchi == (off + 6));
												assert(strcmp(thunkid.linkage_name, id.linkage_name) == 0);
												//TODO: call sites for import thunks can have different local names,
												//so find out which one to use
												//assert(strcmp(thunkid.name, id.name) == 0);
											}
										}
									}
								}
							}
						}
					}
				}	break;

				case DW_TAG_inlined_subroutine:
				{
					//HACK: DW_INL_declared_not_inlined and DW_INL_not_inlined should never be used by this DIE,
					//since DW_TAG_inlined_subroutine is considered as concrete inlined instance. But some
					//buggy compilers set this attribute in the abstract inlined instance to this value,
					//so we need to allow it here.
					assert(id.inlined == DW_INL_inlined || id.inlined == DW_INL_declared_inlined ||
						id.inlined == DW_INL_declared_not_inlined || id.inlined == DW_INL_not_inlined);
					if (id.hasChild)
					{
						if (!id.pchi && id.ranges.type != Invalid)
						{
							pcRange_t bounds;
							if (decodeRanges(id.ranges, &bounds, cu, NULL))
							{
								id.pclo = bounds.pclo;
								id.pchi = bounds.pchi;
							}
						}
						if (id.pclo < id.pchi)
						{
							FrameInfoData& outerframe = getNewPrevFrame(frame, allFrames);
							outerframe.pc = id.pchi;
							frame.type = FrameInfoData::Inline;
							frame.func = id.pclo;
							frame.id.code_addr = id.pclo;
							frame.pc = id.pclo;

							auto& childmap = blockVars[{ idBlock.pclo, idBlock.pchi }].map;
							childmap.try_emplace({ id.pclo, id.pchi });
							lexicalBlocks.push_back(cursor);
							cursor = lexicalBlocks.back().getSubtreeCursor(); // use list value as parent
							idBlocks.push_back(idBlock);
							idBlock = id;
							continue;
						}
					}
				}	break;

				case DW_TAG_formal_parameter:
				case DW_TAG_variable:
					if (id.name)
					{
						pcRange_t parentkey = { 0 }; // root block
						pcRange_t childkey = { idBlock.pclo, idBlock.pchi };
						if (!idBlocks.empty())
						{
							// parent block
							parentkey.pclo = idBlocks.back().pclo;
							parentkey.pchi = idBlocks.back().pchi;
						}
						auto& childmap = blockVars[parentkey].map;
						auto& vars = childmap[childkey].map;
						auto* entry = &vars[{id.name, getTypeByDWARFPtr(cu, id.type, true), id.tag}];
						//HACK: there are no lexical scope informations in go lang, so multiple var definitions
						//need renaming
						//https://blog.golang.org/debugging-go-code-status-report
						if (cu.language == CompilationUnitData::language_go && entry->die_ptr)
						{
							int baselen = strlen(id.name);
							varnames.push_back(std::string(baselen + 1 + num_digits(MAXSIZE_T - 1, 10), '\0'));
							std::string& varname = varnames.back();
							auto itnumstart = varname.begin() + baselen;
							varname.replace(varname.begin(), itnumstart, id.name, baselen);
							varname.replace(itnumstart, itnumstart + 1, 1, '#');
							++itnumstart;
							char numtemp[num_digits(MAXSIZE_T - 1, 10)];
							int type = getTypeByDWARFPtr(cu, id.type, true);
							for (size_t i = 1; i < (MAXSIZE_T - 1); i++)
							{
								_ultoa_s(i, numtemp, 10);
								varname.replace(itnumstart, varname.end(), numtemp);
								entry = &vars[{varname.c_str(), type, id.tag}];
								if (!entry->die_ptr)
									break;
							}
						}

						if (id.location.type == LocListPtr)
						{
							for (const auto& rangeloc : decodeLocationList(id.location, cu, &frame))
							{
								const Location& loc = rangeloc.second;
								addBlockVarLocation(*entry, blockVars, cfachanges, rangeloc.first, loc);
								if (hasfp && loc.is_regrel() && loc.reg == ebp.reg)
									lowestFPOffset = (std::min)(lowestFPOffset, loc.off);
							}
						}
						else if (id.location.type == ExprLoc || id.location.type == Block)
						{
							Location loc = decodeLocation(id.location, cu, &frame);
							addBlockVarLocation(*entry, blockVars, cfachanges, childkey, loc);
							if (hasfp && loc.is_regrel() && loc.reg == ebp.reg)
								lowestFPOffset = (std::min)(lowestFPOffset, loc.off);
						}
						else
						{
							assert(id.location.type == Invalid);
							if (id.external && id.linkage_name)
							{
								unsigned long segOff;
								int seg = img.findSymbol(id.linkage_name, segOff);
								if (seg >= 0)
								{
									unsigned long long off = segOff + img.getSectionVMA(seg);
									Location loc = mkAbs(off);
									auto res = entry->map.insert({ loc, { childkey } });
									assert(res.second);
								}

							}
						}

						if (!entry->die_ptr)
						{
							entry->die_ptr = id.entryPtr;
							entry->external = id.external;
						}
					}
					break;

				case DW_TAG_unspecified_parameters:
					break;

				case DW_TAG_label:
					if (id.name && id.pclo)
					{
						pcRange_t parentkey = { 0 }; // root block
						pcRange_t childkey = { idBlock.pclo, idBlock.pchi };
						if (!idBlocks.empty())
						{
							// parent block
							parentkey.pclo = idBlocks.back().pclo;
							parentkey.pchi = idBlocks.back().pchi;
						}
						auto& childmap = blockVars[parentkey].map;
						auto& vars = childmap[childkey].map;
						auto& entry = vars[{id.name, T_NOTYPE, id.tag}];
						if (entry.die_ptr)
							assert(false);
						entry.die_ptr = id.entryPtr;
						entry.external = id.external;

						Location loc = mkAbs(id.pclo);
						auto res = entry.map.insert({ loc, {childkey} });
						assert(res.second);
					}
					break;

				case DW_TAG_base_type:
					if (useTypedefEnum)
						addUdtSymbol(getTypeByDWARFPtr(cu, id.entryPtr, true), id.name, useGlobalMod);
					break;
				case DW_TAG_typedef:
				case DW_TAG_class_type:
				case DW_TAG_structure_type:
				case DW_TAG_union_type:
				case DW_TAG_enumeration_type:
				case DW_TAG_subrange_type:
					if (!id.name)
						id.name = createUniqueNameForUnnamedType(id.tag, getTypeByDWARFPtr(cu, id.entryPtr), id.decl_file);
					addUdtSymbol(getTypeByDWARFPtr(cu, id.entryPtr, true), id.name, useGlobalMod);
					break;

				case DW_TAG_subprogram:
					// "extern void foo(bar);" declaration inside this proc
					if (id.external && id.declaration && id.prototyped)
						break;
					// fall through if not
				default:
					if (!dwarf_preprocess_die(id.tag))
						printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
						(byte*)cu.header + id.entryOff - (byte*)dbgimg.debug_info, cursor.level, id.code, id.tag);
					break;
				}
				cursor.gotoSibling();
			}
		}

		if (mspdb::vsVersion >= 10)
		{
			//TODO: merge live ranges into root block or use inlinesites
			// append vars with live ranges
			for (const auto& parentblock : blockVars)
			{
				for (const auto& childblock : parentblock.second.map)
				{
					for (const auto& var : childblock.second.map)
					{
						if (!var.second.map.empty())
						{
							if (var.first.tag == DW_TAG_label)
								continue;
							appendLocalVar(var.first.name, var.first.type, var.first.tag == DW_TAG_formal_parameter);
							for (const auto& locranges : var.second.map)
							{
								const Location& loc = locranges.first;

								// optimize range set
								typedef struct { pcRange_t range; std::vector<pcRange_t> gaps; } rangeWithGaps_t;
								std::unordered_map<Location, rangeWithGaps_t> rangesbycfa;

								for (const auto& range : locranges.second)
								{
									const CFAState* rangecfa = findBestCFA(dbgimg, cfastates, range);
									auto it = rangesbycfa.insert({ rangecfa ? rangecfa->cfa : ebp, { range } });
									auto& value = it.first->second;
									if (!it.second)
									{
										value.gaps.push_back({ value.range.pchi, range.pclo });
										value.range.pchi = range.pchi;
									}
								}

								for (const auto& cfarange : rangesbycfa)
								{
									bool fullscope = cfarange.second.range.pclo == childblock.first.pclo &&
										cfarange.second.range.pchi == childblock.first.pchi &&
										cfarange.second.gaps.empty();

									if (cfarange.first.need_deref() && isCFARel(loc)) {
										std::string program = createRangeProgramForVarLocation(var.first.name, loc, cfarange.first, img.isX64());
										appendRangeProg(cfarange.second.range, cfarange.second.gaps, appendString(program.c_str()));
									}
									else if (loc.is_regrel()) {
										baseReg = appendRangeStack(cfarange.second.range, cfarange.second.gaps, loc, cfarange.first, fullscope);
									}
									else if (loc.is_inreg())
										appendRangeReg(cfarange.second.range, cfarange.second.gaps, loc, cfarange.first);
								}
							}
						}
					}
				}
			}

			//TODO: append S_INLINESITEs and its local vars with live ranges
		}

#if 1 // add frameinfo
		int off_frame_sym = cbModSymbols;
		codeview_symbol*frame_sym = (codeview_symbol*)(modSymbols + off_frame_sym);
		frame_sym->frame_info_v2.id = S_FRAMEINFO_V2;
		unsigned long long framesize = cfa ? cfa->cfa.off : ebp.off;
		if (cfa && cfa->cfa.need_deref())
			framesize = lowestFPOffset < 0ll ? -lowestFPOffset : 0; //TODO: calculate framesize if lowestFPOffset is 0
																	//(is there any way to compute the framesize with dwarf info in this case?)
		assert(framesize <= UINT_MAX);
		frame_sym->frame_info_v2.cb_frame = (unsigned int)framesize;
		frame_sym->frame_info_v2.cb_pad = 0; //TODO: calculate frame padding
		frame_sym->frame_info_v2.offpad = 0;
		int cbregs = 0;
		if (cfa)
		{
			cbregs = std::accumulate(cfa->savedregs.cbegin(), cfa->savedregs.cend(), 0,
				[cfa](int& acc, CFAState::regRuleMap_t::const_reference&& right) {
				if (right.first == cfa->returnreg)
					return acc;
				if(isDerefCFARel(right.second))
					return acc + right.second.refsize;
				if (cfa->cfa.need_deref() && right.second.need_deref())
					return acc + right.second.refsize;
				return acc;
			});
			if (cfa->cfa.need_deref())
			{
				PDB_FPO_DATA fpo_data = { 0 };
				std::string fpo_program = createFPOProgramForCFAState(*cfa, img.isX64());
				fpo_data.start = pclo + codeSegOffRVA;
				fpo_data.func_size = pchi - pclo;
				fpo_data.locals_size = (unsigned int)framesize;
				int cbparams = 0;
				pcRange_t rootkey = { 0 };
				pcRange_t childkey = { procid.pclo, procid.pchi };
				auto parentit = blockVars.find(rootkey);
				if (parentit != blockVars.end())
				{
					auto childit = parentit->second.map.find(childkey);
					if (childit != parentit->second.map.end())
					{
						for (const auto& var : childit->second.map)
						{
							if (var.first.tag == DW_TAG_formal_parameter && !var.second.map.empty())
							{
								for (const auto& locranges : var.second.map)
								{
									const Location& loc = locranges.first;
									if (isCFARel(loc) /*|| (loc.is_regrel() && loc.reg == ebp.reg)*/)
									{
										cbparams += img.isX64() ? 8 : 4;
										break;
									}
								}
							}
						}
					}
				}
				fpo_data.params_size = cbparams;
				fpo_data.str_offset = appendString(fpo_program.c_str());
				assert(((unsigned int)(cfa->loc - codeSegOff) - pclo) <= MAXWORD);
				fpo_data.prolog_size = (unsigned short)((unsigned int)(cfa->loc - codeSegOff) - pclo);
				fpo_data.savedregs_size = cbregs;
				appendFPOData(fpo_data);
				proc_sym->proc_v2.debug_start = fpo_data.prolog_size;
				//TODO: set to the offset to pclo using the location in cfa state which reverses the cfa state we used for
				//FPO program
				proc_sym->proc_v2.debug_end = pchi - pclo;
			}
			else if (hasfp)
			{
				assert(cfa->savedregs.find(ebp.reg) != cfa->savedregs.end());
				// frame pointer starts at stack pointer where ebp/rbp was saved, so it is not counted
				cbregs -= img.isX64() ? 8 : 4; // reg size for ebp/rbp
			}
		}
		frame_sym->frame_info_v2.cb_saved_regs = cbregs;
		frame_sym->frame_info_v2.eh_offset = 0; //TODO: find exception handler offset + section
		frame_sym->frame_info_v2.eh_sect = 0;
		frame_sym->frame_info_v2.flags = CV_FIFLAG_OptSpeed;// | CV_FIFLAG_AsyncEH;
		//if (hasfp) {
		//	frame_sym->frame_info_v2.flags |= CV_FIVALUE_encodedParamBasePointer(encodeBasePointerReg(CV_REG_EBP));
		//	frame_sym->frame_info_v2.flags |= CV_FIVALUE_encodedLocalBasePointer(encodeBasePointerReg(CV_REG_EBP));
		//}
		len = sizeof(frame_sym->frame_info_v2);
		for (; len & (align - 1); len++)
			modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
		frame_sym->frame_info_v2.len = len - 2;
		cbModSymbols += len;
#endif

		// append blocks and append stack or reg vars for each block
		int level = 0;
		std::vector<std::pair<blockMap_t::iterator, int>> incomplete;
		for (auto parentit = blockVars.begin(), endit = blockVars.end(); parentit != endit;)
		{
			auto& childmap = parentit->second.map;
			auto childit = childmap.begin();
			pcRange_t childkey = childit->first;
			pcRange_t parentkey = parentit->first;
			auto& varlist = childit->second.map;
			if (!varlist.empty())
				cfa = findBestCFA(dbgimg, cfastates, childkey); // best cfa for complete block

			Location cfaloc = cfa ? cfa->cfa : ebp;
			if (parentkey.pchi || parentkey.pclo)
			{
				// append block if it is not root block
				len = appendLexicalBlock(childkey, cvsBlockOffs.back());
				cvsBlockOffs.push_back(cbModSymbols - len);
			}
			else
			{
				// append labels and parameters for root block
				auto it = varlist.cbegin();
				while (it != varlist.cend())
				{
					if (it->first.tag == DW_TAG_formal_parameter ||
						it->first.tag == DW_TAG_label)
					{
						for (const auto& locranges : it->second.map)
						{
							const Location& loc = locranges.first;
							for (const auto& range : locranges.second)
							{
								const CFAState* rangecfa = findBestCFA(dbgimg, cfastates, range);
								Location rangecfaloc = rangecfa ? rangecfa->cfa : ebp;
								// use only the range that has same best cfa as the block or the range spans over complete block
								if ((range.pclo == childkey.pclo &&
									range.pchi == childkey.pchi) || rangecfaloc == cfaloc)
								{
									if (loc.is_regrel()) {
										baseReg = appendStackVar(it->first.name, it->first.type, loc, rangecfaloc);
										frame_sym = (codeview_symbol*)(modSymbols + off_frame_sym);
										if (!(frame_sym->frame_info_v2.flags & CV_FIMASK_encodedParamBasePointer))
											frame_sym->frame_info_v2.flags |= CV_FIVALUE_encodedParamBasePointer(encodeBasePointerReg(baseReg));
									}
									else if (loc.is_inreg())
										appendRegVar(it->first.name, it->first.type, loc, rangecfaloc);
									else if (loc.is_abs())
									{
										if (it->first.tag == DW_TAG_label)
											appendLabel(it->first.name, loc.off);
										else
										{
											//TODO: append ranged param var with static address location
											//appendLocalVar(it->first.name, it->first.type, true);
										}
									}
									break;
								}
							}
						}
						it = varlist.erase(it);
						continue;
					}
					++it;
				}

				appendEndArg();
			}

			for (const auto& var : varlist)
			{
				assert((parentkey.pchi || parentkey.pclo) ||
					(var.first.tag != DW_TAG_formal_parameter &&
						var.first.tag != DW_TAG_label));
				for (const auto& locranges : var.second.map)
				{
					const Location& loc = locranges.first;
					for (const auto& range : locranges.second)
					{
						const CFAState* rangecfa = findBestCFA(dbgimg, cfastates, range);
						Location rangecfaloc = rangecfa ? rangecfa->cfa : ebp;
						// use only the range that has same best cfa as the block or the range spans over complete block
						if ((range.pclo == childkey.pclo &&
							range.pchi == childkey.pchi) || rangecfaloc == cfaloc)
						{
							if (loc.is_regrel()) {
								baseReg = appendStackVar(var.first.name, var.first.type, loc, rangecfaloc);
								frame_sym = (codeview_symbol*)(modSymbols + off_frame_sym);
								if (!(frame_sym->frame_info_v2.flags & CV_FIMASK_encodedLocalBasePointer))
									frame_sym->frame_info_v2.flags |= CV_FIVALUE_encodedLocalBasePointer(encodeBasePointerReg(baseReg));
							}
							else if (loc.is_inreg()) {
								appendRegVar(var.first.name, var.first.type, loc, rangecfaloc);
							}
							else if (loc.is_abs())
							{
								if (var.first.tag == DW_TAG_label)
									appendLabel(var.first.name, loc.off);
								else
								{
									int seg = img.findSection(loc.off);
									if (seg >= 0)
									{
										unsigned long segOff = (unsigned long)(loc.off - img.getSectionVMA(seg));
										// TODO: differentiate between global and local data
										appendGlobalVar(var.first.name, var.first.type, seg + 1, segOff);
										if (var.second.external)
											int rc = mod->AddPublic2(var.first.name, seg + 1, segOff, CV_PUBSYMFLAGS_cvpsfNone);
									}
								}
							}
							break;
						}
					}
				}
			}

			auto newparentit = blockVars.find(childkey);
			auto nextchildit = childmap.erase(childit);
			if (nextchildit == childmap.end())
			{
				blockVars.erase(parentit);
				newparentit = blockVars.find(childkey); // iterator can be invalid after erase
				if (newparentit == endit)
				{
					int stoplevel = 0;
					if (!incomplete.empty())
					{
						parentit = incomplete.back().first;
						stoplevel = incomplete.back().second;
						incomplete.pop_back();
					}
					else
						parentit = blockVars.begin();

					while (level > stoplevel) {
						appendEnd(cvsBlockOffs.back());
						cvsBlockOffs.pop_back();
						--level;
					}
				}
			}
			else if (newparentit != endit && // if new parent and only if it's realy new (parent!=child)
				(parentkey.pclo != childkey.pclo || parentkey.pchi != childkey.pchi))
				incomplete.push_back({ parentit, level });

			if (newparentit == endit)
			{
				if (parentkey.pchi || parentkey.pclo) // finish only if not root block
				{
					appendEnd(cvsBlockOffs.back());
					cvsBlockOffs.pop_back();
				}
			}
			else
			{
				parentit = newparentit;
				if (parentkey.pchi || parentkey.pclo) // finish only if not root block
					level++;
			}
		}

		appendEnd(cvsBlockOffs.back()); // finish root block
		cvsBlockOffs.pop_back();
		assert(cvsBlockOffs.empty());
	}
	else
	{
		appendEndArg();
		appendEnd(cbModSymbols - len); //proc_sym
	}
	return true;
}

bool CV2PDB::addDWARFCallSite(DWARF_InfoData& callid, const CompilationUnitData& cu, DIECursor cursor, const FrameInfoData* frame)
{
	if (!callid.pclo)
		return false;

	CallSite& callsite = *getCallSiteForPC(callid.pclo, true);
	if (callsite.pc)
		return false; // duplicate

	callsite.pc = callid.pclo;

	if (callid.tail_call)
	{
		// skip over DW_TAG_inlined_subroutine
		DWARF_InfoData idparent;
		for (DIECursor parentCursor = cursor.getParentCursor();
			parentCursor.readAgain(idparent) && idparent.tag != DW_TAG_subprogram
			&& idparent.tag != DW_TAG_subroutine_type;
			parentCursor = parentCursor.getParentCursor())
			;

		if (idparent.entryPtr)
		{
			if (!idparent.all_call_sites &&
				!idparent.all_tail_call_sites)
			{
				/* TYPE_TAIL_CALL_LIST is not interesting in functions where it is
				not complete.  But keep CALL_SITE for look ups via getCallSiteForPC,
				both the initial caller containing the real return address PC and
				the final callee containing the current PC of a chain of tail
				calls do not need to have the tail call list complete.  But any
				function candidate for a virtual tail call frame searched via
				TYPE_TAIL_CALL_LIST must have the tail call list complete to be
				determined unambiguously.  */
			}
			else
			{
				int func_typeId = getTypeByDWARFPtr(cu, idparent.entryPtr);
				assert(func_typeId != T_VOID);
				// not created yet, so can't do more checks
				//const codeview_type* func_type = getTypeData(func_typeId);
				//assert(func_type != NULL &&
				//	(func_type->generic.id == LF_MFUNCTION_V2 ||
				//		func_type->generic.id == LF_PROCEDURE_V2));

				auto* tail_call_list = getTailCallListByType(cu, idparent.entryPtr);
				callsite.tail_call_func_type = func_typeId;
				tail_call_list->push_back(&callsite);
			}
		}
	}

	if (callid.call_site_target.type == Block || callid.call_site_target.type == ExprLoc)
	{
		// block target
		callsite.target_type = CallSite::dwarf_block;
		callsite.target.block = callid.call_site_target;
	}
	else if (callid.call_site_target.type == Ref ||
		(callid.call_site_target.type == Invalid && callid.abstract_origin))
	{
		// to get clean values, read from call_site_target DIE or again from merged DIE
		byte* ref_die = callid.call_site_target.type == Ref ?
			callid.call_site_target.ref : callid.abstract_origin;
		DIECursor origCursor = findCompilationUnitChildCursor(ref_die);
		DWARF_InfoData idorig;
		origCursor.readNext(idorig);
		assert(callid.tag == idorig.tag ||
			(callid.tag == DW_TAG_GNU_call_site && idorig.tag == DW_TAG_subprogram));

		if (idorig.is_declaration())
		{
			// name target
			const char* phys_name = idorig.linkage_name;
			if (!phys_name)
				phys_name = idorig.name;
			callsite.target_type = CallSite::physname;
			callsite.target.physname = phys_name;
		}
		else
		{
			// pc target
			pcRange_t bounds = { idorig.pclo, idorig.pchi };
			if (!bounds.pchi && idorig.ranges.type != Invalid)
			{
				pcRange_t bounds;
				if (!decodeRanges(idorig.ranges, &bounds, origCursor.cu, NULL))
				{
					bounds.pclo = 0;
				}
			}
			if (bounds.pclo)
			{
				callsite.target_type = CallSite::physaddr;
				callsite.target.physaddr = bounds.pclo;
			}
		}
	}

	callsite.cu = cu;

	std::vector<FrameInfoData> subframes;
	if (frame)
	{
		unsigned long long targetpc = callsite.getTargetAddr(frame);
		if (targetpc == -1)
			targetpc = 0; // unknown target (maybe func pointer)

		FrameInfoData targetframe = *frame;
		FrameInfoData& outerframe = getNewPrevFrame(targetframe, subframes);
		outerframe.pc = callid.pclo;
		targetframe.type = FrameInfoData::Normal;
		targetframe.func = targetpc;
		targetframe.id.code_addr = targetpc;
		targetframe.pc = targetpc;
		frame = &getNewPrevFrame(targetframe, subframes);
		const_cast<FrameInfoData&>(*frame).next = NULL; // was only temporary sentinel (targetframe)
	}

	if (cursor.hasChild)
	{
		DIECursor paramCursor = cursor.getSubtreeCursor();
		DWARF_InfoData idparam;
		if (!paramCursor.readNext(idparam))
			assert(false);
		do
		{
			if (idparam.tag != DW_TAG_GNU_call_site_parameter)
				assert(false);

			CallSiteParam parameter;

			//TODO: if merge lead to false values, read again from abstract_origin
			if (idparam.location.type == Invalid && idparam.abstract_origin)
			{
				if (!cu.header->isInBounds(idparam.abstract_origin))
					continue; // DW_OP_GNU_parameter_ref can only reference in same cu
				parameter.loc = mkAbs(idparam.abstract_origin - (byte*)cu.header);
			}
			else if (idparam.location.type == Invalid || idparam.abstract_origin ||
				(idparam.location.type != Block && idparam.location.type != ExprLoc))
			{
				continue;
			}
			else
			{
				Location loc = decodeLocation(idparam.location, cu, frame);
				if (loc.is_inreg() || (loc.is_regrel() && loc.reg == (img.isX64() ? dwarf_reg64_rsp : dwarf_reg32_esp)))
					parameter.loc = loc;
				else
					continue;
			}

			if (idparam.call_site.type != Block && idparam.call_site.type != ExprLoc)
				continue;

			parameter.value = idparam.call_site;
			parameter.data_value.type = Invalid;
			if (idparam.call_site_data.type != Invalid)
				parameter.data_value = idparam.call_site_data;

			callsite.params.push_back(parameter);
		} while (paramCursor.readSibling(idparam));
	}

	return true;
}

std::vector<DWARF_StructMember> CV2PDB::getDWARFStructMembers(byte* typePtr, long long off)
{
	auto& it = mapOffsetToStructMembers.try_emplace(typePtr);
	std::vector<DWARF_StructMember>& members = it.first->second;
	if (it.second)
	{
		DWARF_InfoData structid;
		DIECursor cursor = findCompilationUnitChildCursor(typePtr);

		if (!cursor.readNext(structid))
		{
			assert(false);
		}
		else
		{
			switch (structid.tag)
			{
			case DW_TAG_class_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			{
				int type = getTypeByDWARFPtr(cursor.cu, typePtr);
				const char* name = structid.name ? structid.name : structid.linkage_name;
				if (!name)
					name = createUniqueNameForUnnamedType(structid.tag, type, structid.decl_file);

				// get members for offset 0 and cache them
				members = getDWARFStructMembers(structid, name, cursor.cu, cursor.getSubtreeCursor(), 0);
			}	break;

			default:
				assert(false);
				break;
			}
		}
	}
	// copy cache to result
	std::vector<DWARF_StructMember> result = members;
	if (off)
	{
		// calculate new offset for result
		for (auto&& member : result)
		{
			if (member.kind == DWARF_StructMember::Field ||
				member.kind == DWARF_StructMember::BaseClass)
				member.off += off;
		}
	}
	return result;
}

std::vector<DWARF_StructMember> CV2PDB::getDWARFStructMembers(DWARF_InfoData& structid, const char* structname, const CompilationUnitData& cu, DIECursor cursor, long long off)
{
	bool isunion = structid.tag == DW_TAG_union_type;
	std::vector<DWARF_StructMember> result;

	DWARF_InfoData id;
	DWARF_StructMember member;

#if 0
	if (structid.containing_type && structid.containing_type != structid.entryPtr)
	{
		member.kind = DWARF_StructMember::BaseClass;
		member.off = 0;
		member.unnamed = DWARF_StructMember::Named; // treat as named member, but don't specify name
		member.name = NULL;
		member.type_die = id.type;
		member.type = getTypeByDWARFPtr(cu, structid.containing_type);
		result.push_back(member);
}
#endif

	while (cursor.readNext(id/*, ?true? */))
	{
		member.overloads.clear();
		switch (id.tag)
		{
		case DW_TAG_member:
		{
			long long memberoff = 0;
			if (!isunion)
			{
				Location loc = decodeLocation(id.member_location, cu, 0, DW_AT_data_member_location);
				if (loc.is_abs())
					memberoff = loc.off;
				else
					memberoff = -1;
			}

			if (memberoff >= 0)
			{
				if (id.name && id.name[0] != '\0')
				{
					//printf("    Adding field %s\n", id.name);

					member.kind = DWARF_StructMember::Field;
					member.off = memberoff + off;
					member.unnamed = DWARF_StructMember::Named;
					member.name = id.name;
					member.type_die = id.type;
					member.type = getTypeByDWARFPtr(cu, id.type);
					result.push_back(member);
				}
				else // anonymous member
				{
					// append child members at new base offset
					std::vector<DWARF_StructMember> submembers = getDWARFStructMembers(id.type, memberoff + off);
					result.insert(result.end(), submembers.begin(), submembers.end());
				}
			}
		}	break;
		case DW_TAG_inheritance:
		{
			long long memberoff = -1;
			Location loc = decodeLocation(id.member_location, cu, 0, DW_AT_data_member_location);
			if (loc.is_abs())
				memberoff = loc.off;

			if (memberoff >= 0)
			{
				member.kind = DWARF_StructMember::BaseClass;
				member.off = memberoff + off;
				member.unnamed = DWARF_StructMember::Named; // treat as named member, but don't specify name
				member.name = NULL;
				member.type_die = id.type;
				member.type = getTypeByDWARFPtr(cu, id.type);
				result.push_back(member);
			}
		}	break;
		case DW_TAG_class_type:
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_enumeration_type:
			member.kind = DWARF_StructMember::NestedType;
			member.off = 0;
			member.type_die = id.entryPtr;
			member.type = getTypeByDWARFPtr(cu, id.entryPtr);
			member.unnamed = DWARF_StructMember::Named;
			member.name = id.name ? id.name : id.linkage_name;
			if (!member.name)
				member.name = createUniqueNameForUnnamedType(id.tag, member.type, id.decl_file);
			result.push_back(member);
			break;
		case DW_TAG_template_type_parameter:
		case DW_TAG_template_value_parameter:
			member.kind = DWARF_StructMember::TemplateParam;
			member.off = 0;
			member.type_die = id.type;
			member.type = getTypeByDWARFPtr(cu, id.type);
			member.unnamed = DWARF_StructMember::Named;
			member.name = id.name ? id.name : id.linkage_name;
			//TODO: do something usefull with this info
			//id.isdefault;
			if (id.tag == DW_TAG_template_value_parameter)
			{
				Location loc = decodeLocation(id.const_value, cu);
				assert(loc.is_abs());
				member.off = loc.off;
			}
			result.push_back(member);
			//TODO: implement variadic template evaluation
		case DW_TAG_GNU_template_parameter_pack:
			break;
		case DW_TAG_subprogram:
		{
			member.kind = DWARF_StructMember::Method;
			member.off = 0;
			member.type_die = 0;
			member.type = 0;
			member.unnamed = DWARF_StructMember::Named;
			member.name = id.name;
			if (!id.name)
			{
				/* gcc libiberty name demangler has a bug, if the last component
				   before the function component was an unnamed type, so only
				   check for the function type rather than try to demangle it */
				bool ctor = false;
				bool dtor = false;
				bool conversion = false;
				if (cpp_ismangled_ctor_dtor_or_conversion(id.linkage_name, ctor, dtor, conversion))
				{
					if (ctor)
						member.unnamed = DWARF_StructMember::Constructor;
					else if (dtor)
						member.unnamed = DWARF_StructMember::Destructor;
					else if (conversion)
						member.unnamed = DWARF_StructMember::Conversion;
					else
					{
						assert(false); // never reached
					}
				}
				else
				{
					assert(false);
					//TODO: this case should never happen, but handle it gracefully
					//if (demangleSymbols)
					//{
					//	//TODO: demangle
					//}
					//member.name = id.linkage_name;
				}
			}
			//TODO: check only id.name like in gdb? also note that these are ignored in gdb:
			// read_func_scope: "Ignore functions with missing or empty names.  These are actually
			// illegal according to the DWARF standard."
			bool found = false;
			DWARF_StructMember::MethodInfo overload;
			overload.has_this = getDWARFSubroutineParameters(id, cu, cursor.getSubtreeCursor());
			overload.comp_gen = id.artificial;
			overload.expl = id.explicit_func;
			if (id.access)
				overload.access = (DWARF_StructMember::Access)id.access;
			else if (structid.tag == DW_TAG_class_type)
				overload.access = DWARF_StructMember::Private;
			else
				overload.access = DWARF_StructMember::Public;
			overload.virt = (DWARF_StructMember::Virtuality)id.virtuality;
			overload.virtoff = 0;
			if (overload.virt)
			{
				if (id.vtable_elem_location.type == Block || id.vtable_elem_location.type == ExprLoc)
				{
					Location loc = decodeLocation(id.vtable_elem_location, cu, 0, DW_AT_vtable_elem_location);
					// throw exception?
					assert(!loc.is_invalid());
					if (loc.is_abs()) // Old-style GCC emits index as DW_OP_constu
						overload.virtoff = loc.off * cu.header->addrSize();
					else if (loc.need_deref())
					{
						assert(loc.refsize == cu.header->addrSize());
						assert((loc.valoff % cu.header->addrSize()) == 0);
						overload.virtoff = loc.valoff;
					}
					else
					{
						assert(false);
						overload.virtoff = -1;
					}
				}
				else
				{
					/* GCC does this, as of 2008-08-25; PR debug/37237.  */
					assert(id.vtable_elem_location.type == Invalid);
				}
			}
			overload.type = getTypeByDWARFPtr(cu, id.entryPtr);
			for (auto&& othermember : result)
			{
				if (othermember.kind == DWARF_StructMember::Method &&
					(othermember.unnamed == member.unnamed &&
					(othermember.unnamed != DWARF_StructMember::Named ||
						strcmp(othermember.name, member.name) == 0)))
				{
					othermember.overloads.push_back(overload);
					found = true;
					break;
				}
			}
			if (!found)
			{
				member.overloads.push_back(overload);
				result.push_back(member);
			}
		}	break;
		// ingore member typedefs and modifiers for default evaluation
		case DW_TAG_typedef:
		case DW_TAG_pointer_type:
		case DW_TAG_const_type:
		case DW_TAG_array_type:
		case DW_TAG_volatile_type:
		case DW_TAG_reference_type:
		case DW_TAG_rvalue_reference_type:
			break;
			//TODO: use these tags for member definitions
		case DW_TAG_imported_declaration:
		//case DW_TAG_imported_module:
		//case DW_TAG_imported_unit:
			break;
		default:
			printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
				(unsigned char*)cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
			break;
		}
		cursor.gotoSibling();
	}

	return result;
}

template<class _Ty> inline
bool operator ==(const std::reference_wrapper<_Ty>& lhs, const std::reference_wrapper<_Ty>& rhs)
{
	return &(_Ty&)lhs == &(_Ty&)rhs;
}

int CV2PDB::addDWARFStructure(DWARF_InfoData& structid, const CompilationUnitData& cu, DIECursor cursor)
{
	//printf("Adding struct %s, entryoff %d, abbrev %d\n", structid.name, structid.entryOff, structid.abbrev);

	int fieldlistType = 0;
	int vtableType = 0; // vtable
	int vtablePtrType = 0; // vtable*
	int cvtype = nextUserType++;
	int attr = kPropNone;
	int attrfwrd = kPropIncomplete;
	const char* name = (structid.name ? structid.name : structid.linkage_name);
	if (!name)
		name = createUniqueNameForUnnamedType(structid.tag, cvtype, structid.decl_file);

	auto& it = mapOffsetToStructMembers.try_emplace(structid.entryPtr);
	std::vector<DWARF_StructMember>& members = it.first->second;
	if (it.second)
		members = getDWARFStructMembers(structid, name, cu, cursor, 0); // cursor points to the first member
	int nfields = members.size();
	if (nfields)
	{
		std::vector<std::reference_wrapper<const DWARF_StructMember::MethodInfo>> virtintro;
		std::unordered_map<long long, DWARF_StructMember::MethodInfo> basevirt;
		std::list<std::reference_wrapper<const DWARF_StructMember>> allmembers(members.begin(), members.end());
		std::list<DWARF_StructMember> basemembers;
		int imember = 0;
		for (auto it = std::begin(allmembers); it != std::end(allmembers); it = allmembers.erase(it))
		{
			const DWARF_StructMember& member = *it;
			bool islocal = false;
			// member is defined locally (not on base class) if imember is a valid index into members
			// and the element at this index is the current member of this iteration
			if (imember < nfields && &member == &members[imember])
			{
				imember++;
				islocal = true;
			}
			if (member.kind == DWARF_StructMember::BaseClass)
			{
				auto temp = getDWARFStructMembers(member.type_die, 0); // offset not relevant for methods
				auto baseit = basemembers.end();
				baseit = basemembers.insert(baseit, temp.begin(), temp.end());
				allmembers.insert(std::next(it), baseit, basemembers.end());
			}
			else if (member.kind == DWARF_StructMember::Method)
			{
				for (const auto& overload : member.overloads)
				{
					if (overload.virt != DWARF_StructMember::None)
					{
						if (!islocal)
							basevirt.insert({ overload.virtoff, overload });
						else if (basevirt.find(overload.virtoff) == basevirt.end())
							virtintro.push_back(overload);
					}
				}
			}
		}

		int nvirt = basevirt.size() + virtintro.size();
		if (nvirt)
		{
			vtableType = addDWARFVTShape(nvirt, &vtablePtrType);
		}

		checkDWARFTypeAlloc(100);
		codeview_reftype* fl = (codeview_reftype*)(dwarfTypes + cbDwarfTypes);
		int flbegin = cbDwarfTypes;
		fl->fieldlist.id = LF_FIELDLIST_V2;
		cbDwarfTypes += 4;
		fieldlistType = nextDwarfType++;

		if (nvirt && basevirt.size() == 0)
		{
			cbDwarfTypes += addFieldVFuncTable((codeview_fieldtype*)fl->fieldlist.list, vtablePtrType);
		}

		for (const auto& member : members)
		{
			switch (member.kind)
			{
			case DWARF_StructMember::Field:
			{
				checkDWARFTypeAlloc(kMaxNameLen + 100);
				codeview_fieldtype* dfieldtype = (codeview_fieldtype*)(dwarfTypes + cbDwarfTypes);
				cbDwarfTypes += addFieldMember(dfieldtype, CV_fldattr_public, member.off, member.type, member.name);
			}	break;
			case DWARF_StructMember::BaseClass:
			{
				checkDWARFTypeAlloc(100);
				codeview_fieldtype* bc = (codeview_fieldtype*)(dwarfTypes + cbDwarfTypes);
				cbDwarfTypes += addFieldBaseClass(bc, CV_fldattr_public, member.off, member.type);
			}	break;
			case DWARF_StructMember::NestedType:
			{
				checkDWARFTypeAlloc(kMaxNameLen + 100);
				codeview_fieldtype* dfieldtype = (codeview_fieldtype*)(dwarfTypes + cbDwarfTypes);
				cbDwarfTypes += addFieldNestedType(dfieldtype, member.type, member.name);
				attr |= kPropHasNested;
			}	break;
			case DWARF_StructMember::Method:
			{
				char namebuf[kMaxNameLen];
				checkDWARFTypeAlloc(kMaxNameLen + 100);
				codeview_fieldtype* dfieldtype = (codeview_fieldtype*)(dwarfTypes + cbDwarfTypes);
				const char* membername = member.name;
				const char* namefmt;
				switch (member.unnamed)
				{
				case DWARF_StructMember::Constructor:
					namefmt = "%s";
					goto case_Unnamed;
				case DWARF_StructMember::Destructor:
					namefmt = "~%s";
					goto case_Unnamed;
				case DWARF_StructMember::Conversion:
					namefmt = "operator %s";
				case_Unnamed:
					snprintf(namebuf, sizeof(namebuf), namefmt, name);
					membername = namebuf;
					break;
				case DWARF_StructMember::Named:
					break;
				default:
					assert(false);
					break;
				}
				if (member.overloads.size() == 1)
				{
					const auto& single = member.overloads[0];
					int attr = dwarf_to_cv_fldattr(single, std::contains(virtintro, std::ref(single)));
					cbDwarfTypes += addFieldSingleMethod(dfieldtype, attr, single.type, (unsigned long)single.virtoff, membername);
				}
				else
					cbDwarfTypes += addFieldMethodList(dfieldtype, member.overloads.size(), nextDwarfType++, membername);
			}	break;
			case DWARF_StructMember::TemplateParam:
				break;
			default:
				assert(false);
				break;
			}
		}

		fl = (codeview_reftype*)(dwarfTypes + flbegin);
		fl->fieldlist.len = cbDwarfTypes - flbegin - 2;

		for (const auto& member : members)
		{
			if (member.kind == DWARF_StructMember::Method &&
				member.overloads.size() > 1)
			{
				checkDWARFTypeAlloc(member.overloads.size() * sizeof(codeview_mltype));
				codeview_reftype* ml = (codeview_reftype*)(dwarfTypes + cbDwarfTypes);
				int mlbegin = cbDwarfTypes;
				ml->methodlist.id = LF_METHODLIST_V2;
				cbDwarfTypes += offsetof(codeview_reftype, methodlist.list);

				for (const auto& overload : member.overloads)
				{
					codeview_mltype* method = (codeview_mltype*)(dwarfTypes + cbDwarfTypes);
					int attr = dwarf_to_cv_fldattr(overload, std::contains(virtintro, std::ref(overload)));
					cbDwarfTypes += addMethodListMethod(method, attr, overload.type, (unsigned long)overload.virtoff);
				}

				ml = (codeview_reftype*)(dwarfTypes + mlbegin);
				ml->methodlist.len = cbDwarfTypes - mlbegin - 2;
			}
		}
	}

	checkUserTypeAlloc(kMaxNameLen + 100);
	codeview_type* cvtfwrd = (codeview_type*)(userTypes + cbUserTypes); // used from other types or in recursion
	codeview_type* cvt = (codeview_type*)(dwarfTypes + cbDwarfTypes); // used from symbols

	DWARF_InfoData idparent;
	DIECursor parentCursor = cursor.getParentCursor().getParentCursor(); // skip one level
	if (parentCursor.readAgain(idparent))
	{
		switch (idparent.tag)
		{
		case DW_TAG_class_type:
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			attr |= kPropIsNested;
			attrfwrd |= kPropIsNested;
			break;
		default:
			break;
		}
	}
	long long bytesize = getDWARFByteSize(structid, cu);
	if (bytesize == -1 && structid.is_declaration())
		bytesize = 0;
	int lenfwrd = 0;
	int len = 0;
	switch (structid.tag)
	{
	case DW_TAG_class_type:
		lenfwrd = addClass(cvtfwrd, 0, 0, attrfwrd, 0, 0, 0, name);
		if (fieldlistType)
			len = addClass(cvt, nfields, fieldlistType, attr, 0, vtableType, bytesize, name);
		break;
	case DW_TAG_structure_type:
		lenfwrd = addStruct(cvtfwrd, 0, 0, attrfwrd, 0, 0, 0, name);
		if (fieldlistType)
			len = addStruct(cvt, nfields, fieldlistType, attr, 0, vtableType, bytesize, name);
		break;
	case DW_TAG_union_type:
		lenfwrd = addUnion(cvtfwrd, 0, 0, attrfwrd, 0, name);
		if (fieldlistType)
			len = addUnion(cvt, nfields, fieldlistType, attr, bytesize, name);
		break;
	case DW_TAG_interface_type:
		assert(fieldlistType != 0);
		// no forward defn for interfaces
		if (!fieldlistType)
			fieldlistType = createEmptyFieldListType();
		lenfwrd = addInterface(cvtfwrd, nfields, fieldlistType, attr, 0, 0, bytesize, name);
		break;
	default:
		assert(false);
		break;
	}
	cbUserTypes += lenfwrd;
	cbDwarfTypes += len;

	//ensureUDT()?
	if (fieldlistType && structid.tag != DW_TAG_interface_type)
	{
		int udttype = nextDwarfType++;
		assert(mapOffsetToUdtType[structid.entryPtr] == cvtype);
		mapOffsetToUdtType[structid.entryPtr] = udttype;
	}
	return cvtype;
}

int CV2PDB::addDWARFEnum(DWARF_InfoData& enumid, const CompilationUnitData& cu, DIECursor cursor)
{
	int fieldlistType = 0;
	int nfields = 0;
	int attr = kPropNone;
	if (cu.header)
	{
		checkDWARFTypeAlloc(100);
		codeview_reftype* fl = (codeview_reftype*)(dwarfTypes + cbDwarfTypes);
		int flbegin = cbDwarfTypes;
		fl->fieldlist.id = LF_FIELDLIST_V2;
		cbDwarfTypes += 4;

		DWARF_InfoData id;
		while (cursor.readNext(id))
		{
			switch (id.tag)
			{
			case DW_TAG_enumerator:
				if (id.name)
				{
					Location loc = decodeLocation(id.const_value, cu);

					if (loc.is_abs())
					{
						checkDWARFTypeAlloc(kMaxNameLen + 100);
						codeview_fieldtype* dfieldtype = (codeview_fieldtype*)(dwarfTypes + cbDwarfTypes);
						cbDwarfTypes += addFieldEnumerate(dfieldtype, id.name, loc.off);
						nfields++;
					}
				}
				break;
			default:
				printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
					(unsigned char*)cursor.cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
				assert(false);
				break;
			}
			cursor.gotoSibling();
		}
		fl = (codeview_reftype*)(dwarfTypes + flbegin);
		fl->fieldlist.len = cbDwarfTypes - flbegin - 2;
		fieldlistType = nextDwarfType++;
	}
	checkUserTypeAlloc(kMaxNameLen + 100);
	codeview_type* cvt = (codeview_type*)(userTypes + cbUserTypes);

	const char* name = (enumid.name ? enumid.name : enumid.linkage_name);
	if (!name)
		name = createUniqueNameForUnnamedType(enumid.tag, nextUserType, enumid.decl_file);

	DWARF_InfoData idparent;
	DIECursor parentCursor = cursor.getParentCursor().getParentCursor(); // skip one level
	if (parentCursor.readAgain(idparent))
	{
		switch (idparent.tag)
		{
		case DW_TAG_class_type:
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
			attr |= kPropIsNested;
			break;
		default:
			break;
		}
	}

	//TODO: do something usefull with this info
	bool is_enum_class = enumid.enum_class;

	int basetype = 0;
	long long bytesize = getDWARFByteSize(enumid, cu);
	switch (bytesize)
	{
	case 1:		basetype = T_CHAR;		break;
	case 2:		basetype = T_INT2;		break;
	case 4:		basetype = T_INT4;		break;
	case 8:		basetype = T_INT8;		break;
	default:		break;
	}
	if (enumid.type)
	{
		basetype = getTypeByDWARFPtr(cu, enumid.type);
		if (basetype < nextUserType)
		{
			while (const codeview_type* cvtbase = getUserTypeData(basetype)) {
				if (cvtbase->generic.id == LF_MODIFIER_V2)
					basetype = cvtbase->modifier_v2.type;
				else
					break;
			}
		} //TODO: else
	}
	int len = addEnum(cvt, nfields, fieldlistType, attr, basetype, name);
	cbUserTypes += len;

	int cvtype = nextUserType++;
	return cvtype;
}

int CV2PDB::getDWARFSubrangeType(DWARF_InfoData& id, const CompilationUnitData& cu)
{
	assert(id.tag == DW_TAG_subrange_type);
	byte* type = id.type;
	DWARF_Attribute* attrs[] = { &id.lower_bound, &id.upper_bound, &id.count };
	for (size_t i = 0; type == NULL && i < ARRAYSIZE(attrs); i++)
	{
		if (attrs[i]->type == Ref)
		{
			DIECursor refCursor = findCompilationUnitChildCursor(attrs[i]->ref);
			DWARF_InfoData idref;
			refCursor.readNext(idref);
			type = idref.type;
			break;
		}
	}
	if (type != NULL)
		return getTypeByDWARFPtr(cu, id.type);
	return img.isX64() ? T_INT8 : T_INT4;
}

long long CV2PDB::getDWARFSubrangeBounds(DWARF_InfoData & id, const CompilationUnitData& cu, long long & upperBound)
{
	long long lowerBound = 0; //TODO: use language default
	upperBound = -1; // means unknown
	if (id.lower_bound.type == Ref)
	{
		DIECursor refCursor = findCompilationUnitChildCursor(id.lower_bound.ref);
		DWARF_InfoData idref;
		refCursor.readNext(idref);
		// TODO: evaluate referenced DIE
	}
	else
	{
		Location loc = decodeLocation(id.lower_bound, cu, 0, DW_AT_lower_bound);
		if (loc.is_abs())
			lowerBound = loc.off;
		else
			assert(id.lower_bound.type == Invalid);
	}

	if (id.upper_bound.type != Invalid)
	{
		if (id.upper_bound.type == Ref)
		{
			DIECursor refCursor = findCompilationUnitChildCursor(id.upper_bound.ref);
			DWARF_InfoData idref;
			refCursor.readNext(idref);
			// TODO: evaluate referenced DIE
		}
		else
		{
			// fake a frame, so non-constant expr can be decoded as well
			FrameInfoData frame;
			frame.base = mkCFARel(0);
			Location loc = decodeLocation(id.upper_bound, cu, &frame, DW_AT_upper_bound);
			if (loc.is_abs())
				upperBound = loc.off;
			// if it's non-constant expr, it is a gcc extension for variable-length automatic arrays,
			// so return -1, because it's unknown at compile-time
			else if (!isDerefCFARel(loc))
				assert(false); // only complain if it's not a non-constant expr
		}
	}
	else if (id.count.type != Invalid)
	{
		if (id.count.type == Ref)
		{
			DIECursor refCursor = findCompilationUnitChildCursor(id.count.ref);
			DWARF_InfoData idref;
			refCursor.readNext(idref);
			// TODO: evaluate referenced DIE
		}
		else
		{
			Location loc = decodeLocation(id.count, cu, 0, DW_AT_lower_bound);
			if (loc.is_abs())
				upperBound = loc.off - (1ll - lowerBound);
			else
				assert(false);
		}
	}
	return lowerBound;
}

long long CV2PDB::getDWARFArrayBounds(DWARF_InfoData& arrayid,
	DIECursor cursor, long long& upperBound)
{
	long long lowerBound = 0;

	if (cursor.cu.header)
	{
		DWARF_InfoData id;
		while (cursor.readNext(id, true))
		{
			int cvid = -1;
			if (id.tag == DW_TAG_subrange_type)
			{
				lowerBound = getDWARFSubrangeBounds(id, cursor.cu, upperBound);
			}
			else
			{
				printf("\r" __FUNCTION__ ":0x%08x, level = %d, id.code = %d, id.tag = %d\n",
					(unsigned char*)cursor.cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
			}
			cursor.gotoSibling();
		}
	}
	return lowerBound;
}

long long CV2PDB::getDWARFByteSize(DWARF_InfoData & id, const CompilationUnitData& cu)
{
	long long bytesize = -1;
	if (id.byte_size.type != Invalid)
	{
		if (id.byte_size.type == Ref)
		{
			DIECursor refCursor = findCompilationUnitChildCursor(id.byte_size.ref);
			DWARF_InfoData idref;
			refCursor.readNext(idref);
			// TODO: evaluate referenced DIE
		}
		else
		{
			Location loc = decodeLocation(id.byte_size, cu, 0, DW_AT_byte_size);
			if (loc.is_abs())
				bytesize = loc.off;
		}
	}
	return bytesize;
}

int CV2PDB::addDWARFArray(DWARF_InfoData& arrayid, DIECursor cursor)
{
	long long upperBound, lowerBound = getDWARFArrayBounds(arrayid, cursor, upperBound);

	checkUserTypeAlloc(kMaxNameLen + 100);
	codeview_type* cvt = (codeview_type*)(userTypes + cbUserTypes);

	cvt->array_v2.id = v3 ? LF_ARRAY_V3 : LF_ARRAY_V2;
	cvt->array_v2.elemtype = getTypeByDWARFPtr(cursor.cu, arrayid.type);
	cvt->array_v2.idxtype = T_INT4;
	int len = (BYTE*)&cvt->array_v2.arrlen - (BYTE*)cvt;
	long long size = (upperBound - lowerBound + 1) * getDWARFTypeSize(arrayid.type);
	len += write_numeric_leaf(size, &cvt->array_v2.arrlen);
	((BYTE*)cvt)[len++] = 0; // empty name
	for (; len & 3; len++)
		userTypes[cbUserTypes + len] = 0xf4 - (len & 3);
	cvt->array_v2.len = len - 2;

	cbUserTypes += len;

	int cvtype = nextUserType++;
	return cvtype;
}

bool CV2PDB::addDWARFTypes()
{
	int datasize = cbGlobalTypes;
	byte* data = (byte*)malloc(datasize);
	memcpy(data, globalTypes, cbGlobalTypes);

	if (useGlobalMod)
	{
		if (cbUserTypes > 0 || cbDwarfTypes)
		{
			datasize += cbUserTypes + cbDwarfTypes;
			data = (byte*)safe_realloc(data, datasize);
			int off = cbGlobalTypes;
			if (cbUserTypes > 0)
			{
				memcpy(data + off, userTypes, cbUserTypes);
				off += cbUserTypes;
			}
			if (dwarfTypes)
			{
				memcpy(data + off, dwarfTypes, cbDwarfTypes);
				off += cbDwarfTypes;
			}
			int rc = globalMod()->AddTypes(data, off);
			if (rc <= 0)
				return setError("cannot add type info to module");
		}
	}
	else
	{
		for (int m = 0; m < countEntries; m++)
		{
			if (cbModTypes[m])
			{
				if (datasize < cbGlobalTypes + cbModTypes[m])
				{
					datasize = cbGlobalTypes + cbModTypes[m];
					data = (byte*)safe_realloc(data, datasize);
				}
				memcpy(data + cbGlobalTypes, modTypes[m], cbModTypes[m]);
				delete[] modTypes[m];
				modTypes[m] = NULL;
				int rc = modules[m]->AddTypes(data, cbGlobalTypes + cbModTypes[m]);
				if (rc <= 0)
					return setError("cannot add type info to module");
			}
		}
		delete[] modTypes;
		modTypes = NULL;
	}
	free(data);

	return true;
}

bool CV2PDB::addDWARFSectionContrib(mspdb::Mod* mod, unsigned long long pclo, unsigned long long pchi)
{
	int segIndex = img.findSection(pclo);
	if (segIndex >= 0)
	{
		unsigned long long segbase = img.getSectionVMA(segIndex);
		if ((pclo - segbase) > ULONG_MAX)
			return setError("cannot add section contribution to module: offset > ULONG_MAX");
		if ((pchi - pclo) > ULONG_MAX)
			return setError("cannot add section contribution to module: size > ULONG_MAX");
		int segFlags = img.getSection(segIndex).Characteristics;
		int rc = mod->AddSecContrib(segIndex + 1, (long)(pclo - segbase), (long)(pchi - pclo), segFlags);
		if (rc <= 0)
			return setError("cannot add section contribution to module");
		return true;
	}
	return false;
}

bool CV2PDB::addDWARFModule(int imod, const CompilationUnitData& cu, bool create, bool import)
{
#if !FULL_CONTRIB
	if (/*id.dir &&*/ cu.name)
	{
		char path[MAX_PATH];
		path[0] = '\0';
		const char* objname = path;
		if (import)
		{
			strcpy_s(path, "Import:");
			strcat_s(path, cu.name);
		}
		else if (cu.dir)
		{
			_makepath_s(path, NULL, cu.dir, NULL, NULL);
			strcat_s(path, cu.name);
			if (!_fullpath(path, path, sizeof(path)))
				return false;
		}
		else if (!_fullpath(path, cu.name, sizeof(path)))
			return false;

		if (create)
		{
			assert(imod < countEntries);
			unsigned short newimod;
			unsigned long trycount = 0;
			char temp[MAX_PATH];
			mspdb::Mod* mod;
			size_t objnamelen;
			do
			{
				//TODO: create better module names
				const char* modname = objname;
				if (trycount)
				{
					modules[imod] = NULL;
					modname = temp;
					const size_t ndigits = num_digits(MAXUINT, 10);
					if (trycount == 1)
					{
						strcpy_s(temp, objname);
						objnamelen = strnlen_s(objname, MAX_PATH);
						if ((objnamelen + ndigits + 1) >= MAX_PATH)
							return setError("cannot create module name");
					}
					_ultoa_s(trycount, temp + objnamelen, ndigits + 1, 10);
				}
				int rc = dbi->OpenMod(modname, objname, &modules[imod]);
				mod = modules[imod];
				if (rc <= 0 || !mod)
					return setError("cannot create mod");

				rc = mod->QueryImod(&newimod);
				if (rc <= 0)
					return setError("cannot query for imod");
				trycount++;
			} while ((newimod - 1) != imod); // 1-based

			if (!cu.ranges.empty())
			{
				for (const auto& range : cu.ranges)
				{
					//printf("%s %s %x - %x\n", dir, name, pclo, pchi);
					if (!addDWARFSectionContrib(mod, range.pclo, range.pchi))
						return false;
				}
			}
			else if (cu.pclo < cu.pchi)
			{
				//printf("%s %s %x - %x\n", dir, name, pclo, pchi);
				if (!addDWARFSectionContrib(mod, cu.pclo, cu.pchi))
					return false;
			}
			// else needs section contribution?
		}
		else
		{
			mspdb::Mod* mod = modules[imod];

			checkModSymbolAlloc(100 + kMaxNameLen * 3);

			const unsigned int align = 4;
			codeview_symbol*dsym = (codeview_symbol*)(modSymbols + cbModSymbols);
			dsym->objname_v1.id = v3 ? S_OBJNAME_V3 : S_OBJNAME_V1;
			dsym->objname_v1.signature = 0;
			int len = cstrcpy_v(v3, (BYTE*)&dsym->objname_v1.p_name, import ? cu.name : objname, false);
			len += sizeof(dsym->objname_v1) - sizeof(dsym->objname_v1.p_name);
			for (; len & (align - 1); len++)
				modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
			dsym->objname_v1.len = len - 2;
			cbModSymbols += len;

			dsym = (codeview_symbol*)(modSymbols + cbModSymbols);
			memset(&dsym->compiland2_v2, 0, sizeof(dsym->compiland2_v2) - sizeof(dsym->compiland2_v2.p_version));
			dsym->compiland2_v2.id = v3 ? S_COMPILAND2_V3 : S_COMPILAND2_V2;
			if (import)
				dsym->compiland2_v2.flags = CV_COMPILEMASK_LANGUAGE & CV_CFL_LINK;
			else
				dsym->compiland2_v2.flags = CV_COMPILEMASK_LANGUAGE & dwarf_to_cv_lang(cu.language);
			dsym->compiland2_v2.machine = img.isX64() ? CV_CFL_X64 : CV_CFL_PENTIUMII; //0x06: Pentium Pro/II, 0xd0: x64
			len = sizeof(dsym->compiland2_v2) - sizeof(dsym->compiland2_v2.p_version);
			if (cu.producer)
			{
				size_t prodlen = strlen(cu.producer) + 1;
				const char* cmdbeg = strchr(cu.producer, '-');
				if (cmdbeg)
					prodlen = cmdbeg - cu.producer;
				char* prod = new char[prodlen];
				strncpy(prod, cu.producer, prodlen - 1);
				prod[prodlen - 1] = 0;
				len += cstrcpy_v(v3, (BYTE*)&dsym->compiland2_v2.p_version, prod, false);
				delete[] prod;
				if (cu.dir)
				{
					strcpy((char*)&dsym->compiland2_v2 + len, "cwd");
					len += sizeof("cwd");
					strcpy((char*)&dsym->compiland2_v2 + len, cu.dir);
					len += strlen(cu.dir) + 1;
				}
				if (cmdbeg)
				{
					strcpy((char*)&dsym->compiland2_v2 + len, "cmd");
					len += sizeof("cmd");
					strcpy((char*)&dsym->compiland2_v2 + len, cmdbeg);
					len += strlen(cmdbeg) + 1;
				}
				strcpy((char*)&dsym->compiland2_v2 + len, "src");
				len += sizeof("src");
				strcpy((char*)&dsym->compiland2_v2 + len, cu.name);
				len += strlen(cu.name) + 1;
			}
			else
				len += cstrcpy_v(v3, (BYTE*)&dsym->compiland2_v2.p_version, "cv2pdb", false);

			modSymbols[cbModSymbols + (len++)] = 0; // terminate string block
			for (; len & (align - 1); len++)
				modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
			dsym->compiland2_v2.len = len - 2;
			cbModSymbols += len;
		}
	}
#endif
	return true;
}

int CV2PDB::addDWARFBasicType(const char*name, int encoding, int byte_size)
{
	int type = 0, mode = 0, size = 0;
	switch (encoding)
	{
	case DW_ATE_boolean:        type = 3; break;
	case DW_ATE_complex_float:  type = 5; byte_size /= 2; break;
	case DW_ATE_float:          type = 4; break;
	case DW_ATE_signed:         type = 1; break;
	case DW_ATE_signed_char:    type = 7; break;
	case DW_ATE_unsigned:       type = 2; break;
	case DW_ATE_unsigned_char:  type = 7; break;
	case DW_ATE_imaginary_float:type = 4; break;
	case DW_ATE_UTF:            type = 7; break;
	default:
		setError("unknown basic type encoding");
	}
	switch (type)
	{
	case 1: // signed
	case 2: // unsigned
	case 3: // boolean
		switch (byte_size)
		{
		case 1: size = 0; break;
		case 2: size = 1; break;
		case 4: size = 2; break;
		case 8: size = 3; break;
		case 16: size = 4; break; // __int128? experimental, type exists with GCC for Win64
		default:
			setError("unsupported integer type size");
		}
		break;
	case 4:
	case 5:
		switch (byte_size)
		{
		case 4:  size = 0; break;
		case 8:  size = 1; break;
		case 10: size = 2; break;
		case 12: size = 2; break; // with padding bytes
		case 16: size = 3; break;
		case 6:  size = 4; break;
		default:
			setError("unsupported real type size");
		}
		break;
	case 7:
		switch (byte_size)
		{
		case 1:  size = 0; break;
		case 2:  size = encoding == DW_ATE_signed_char ? 2 : 3; break;
		case 4:  size = encoding == DW_ATE_signed_char ? 4 : 5; break;
		case 8:  size = encoding == DW_ATE_signed_char ? 6 : 7; break;
		default:
			setError("unsupported real int type size");
		}
	}
	int t = size | (type << 4);
	t = translateType(t);
	int cvtype = appendTypedef(t, name, mode, false);
	return cvtype;
}

int CV2PDB::addDWARFVTShape(int count, int* vtablePtrType)
{
	std::unordered_map<int, int>::iterator it = mapCountToVTShapeType.find(count);
	if (it != mapCountToVTShapeType.end())
	{
		if (vtablePtrType)
			*vtablePtrType = it->second + 1;
		return it->second;
	}

	int vtableType = nextDwarfType++;
	if (vtablePtrType)
		*vtablePtrType = nextDwarfType;
	nextDwarfType++;
	mapCountToVTShapeType.insert(std::make_pair(count, vtableType));

	int fullbytes = (count >> 1);
	int halfbytes = count & 1;
	int len = (sizeof(codeview_reftype::vtshape_v1) - sizeof(codeview_reftype::vtshape_v1.desc)) + fullbytes + halfbytes;
	checkDWARFTypeAlloc(len + sizeof(codeview_type::pointer_v2));

	// vtable
	codeview_reftype* rdtype = (codeview_reftype*)(dwarfTypes + cbDwarfTypes);
	rdtype->vtshape_v1.id = LF_VTSHAPE_V1;
	rdtype->vtshape_v1.num = count;
	memset(&rdtype->vtshape_v1.desc[0], CV_VTS_near32 | (CV_VTS_near32 << 4), fullbytes);
	if (halfbytes)
		rdtype->vtshape_v1.desc[fullbytes] = CV_VTS_near32;

	unsigned char* p = (unsigned char*)rdtype;
	for (; len & 3; len++)
		p[len] = 0xf4 - (len & 3);
	rdtype->vtshape_v1.len = len - 2;
	cbDwarfTypes += len;

	// vtable*
	const int pointerAttr = img.isX64() ? CV_PTR_size(8) | CV_PTR_64 : CV_PTR_size(4) | CV_PTR_NEAR32;
	cbDwarfTypes += addPointerType(dwarfTypes + cbDwarfTypes, vtableType, pointerAttr);

	return vtableType;
}

std::vector<CallSite*>* CV2PDB::getTailCallListByType(const CompilationUnitData& cu, byte* typePtr)
{
	if (typePtr && !cu.header->isInBounds(typePtr)) // type from another CU
	{
		assert(false);
		return NULL; // not supported yet
	}
	return &mapOffsetToTailCallList[typePtr];
}

int CV2PDB::getTypeByDWARFPtr(const CompilationUnitData& cu, byte* ptr, bool udt)
{
	if (ptr && !cu.header->isInBounds(ptr)) // type from another CU
	{
		assert(false);
		return T_NOTYPE; // not supported yet
	}
	std::unordered_map<byte*, int>& map = udt ? mapOffsetToUdtType : mapOffsetToType;
	std::unordered_map<byte*, int>::iterator it = map.find(ptr);
	if (it == map.end())
		return T_VOID; // void
	return it->second;
}

const DWARF_InfoData* CV2PDB::getThunkByImportOffset(unsigned long long off)
{
	auto it = mapImportsToThunks.find(off);
	if (it == mapImportsToThunks.end())
		return NULL;
	return &it->second;
}


long long CV2PDB::getDWARFTypeSize(byte* typePtr)
{
	DWARF_InfoData id;
	DIECursor cursor = findCompilationUnitChildCursor(typePtr);

	if (!cursor.readNext(id))
		return 0;

	long long bytesize = getDWARFByteSize(id, cursor.cu);

	if (bytesize > 0)
		return bytesize;

	switch (id.tag)
	{
	case DW_TAG_ptr_to_member_type:
	case DW_TAG_reference_type:
	case DW_TAG_pointer_type:
		return cursor.cu.header->addrSize();
	case DW_TAG_array_type:
	{
		long long upperBound, lowerBound = getDWARFArrayBounds(id, cursor.getSubtreeCursor(), upperBound);
		return (upperBound + lowerBound + 1) * getDWARFTypeSize(id.type);
	}
	default:
		if (id.type)
			return getDWARFTypeSize(id.type);
		break;
	}
	return 0;
}

int CV2PDB::getDWARFTypeCVModifier(byte* typePtr, bool term_indir)
{
	DWARF_InfoData id;
	DIECursor cursor = findCompilationUnitChildCursor(typePtr);

	int cvmod = 0;
	while (cursor.readNext(id))
	{
		switch (id.tag)
		{
			// reset mods if indirection
		case DW_TAG_ptr_to_member_type:
		case DW_TAG_reference_type:
		case DW_TAG_pointer_type:
		case DW_TAG_array_type:
			if (term_indir) // don't follow indirection
				return cvmod;
			cursor = findCompilationUnitChildCursor(id.type);
			cvmod = 0;
			continue;

			// set mods
		case DW_TAG_const_type:
			cursor = findCompilationUnitChildCursor(id.type);
			cvmod |= CV_modifier_const;
			break;
		case DW_TAG_volatile_type:
			cursor = findCompilationUnitChildCursor(id.type);
			cvmod |= CV_modifier_volatile;
			break;

			// terminator
		case DW_TAG_base_type:
		case DW_TAG_class_type:
		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_subroutine_type:
		default:
			return cvmod;
		}
	}
	return cvmod;
}

template <class _Kty>
struct pairvisitor
{
	static std::unordered_map<_Kty, int> visitedleft;
	static std::unordered_map<_Kty, int> visitedright;
	typedef typename std::unordered_map<_Kty, int>::iterator iterator;

	inline pairvisitor(const _Kty& left, const _Kty& right)
		: is_equal(false), _left(visitedleft.end()), _right(visitedright.end())
	{
		auto leftpos = visitedleft.insert({ left, visitedleft.size() });
		auto rightpos = visitedright.insert({ right, visitedright.size() });
		if (leftpos.second)
			_left = leftpos.first;
		if (rightpos.second)
			_right = rightpos.first;
		both_visited = !leftpos.second && !rightpos.second;
		if (both_visited)
			is_equal = leftpos.first->second == rightpos.first->second;
	}

	inline ~pairvisitor()
	{
		if (_left != visitedleft.end())
			visitedleft.erase(_left);
		if (_right != visitedright.end())
			visitedright.erase(_right);
	}

	bool is_equal;
	bool both_visited;
	iterator _left;
	iterator _right;
};
template <class _Kty> std::unordered_map<_Kty, int> pairvisitor<_Kty>::visitedleft;
template <class _Kty> std::unordered_map<_Kty, int> pairvisitor<_Kty>::visitedright;

static size_t test_count = 0;

static bool equalDWARFTypes(byte* typePtrLeft, byte* typePtrRight)
{
	/*if (test_count++ >= 500000)
		exit(0);*/
	if (typePtrLeft == typePtrRight)
		return true;

	if (!typePtrLeft || !typePtrRight) // (typePtrLeft == NULL) ^ (typePtrRight == NULL)
		return false;

	pairvisitor<void*> visited(typePtrLeft, typePtrRight);
	if (visited.both_visited)
		return visited.is_equal;

	DWARF_InfoData idleft, idright;
	DIECursor leftcursor = findCompilationUnitChildCursor(typePtrLeft),
		rightcursor = findCompilationUnitChildCursor(typePtrRight);

	// read the root DIEs
	bool readleft = leftcursor.readNext(idleft), readright = rightcursor.readNext(idright);
	if (readleft != readright)
		return false;
	if (!readleft)
		return true;
	// only compare the subtrees not siblings of both types
	leftcursor.gotoSubtree();
	rightcursor.gotoSubtree();

	do
	{
		if (!equalDWARFTypes(idleft.type, idright.type))
			return false;
		// types already checked so don't compare the pointers
		idleft.type = NULL;
		idright.type = NULL;
		// ignore the code positions as long as we can't calculate the absolute CU-independent position
		idleft.decl_column = idleft.decl_file = idleft.decl_line = 0;
		idright.decl_column = idright.decl_file = idright.decl_line = 0;
		if (idleft != idright)
			return false;
	} while ((readleft = leftcursor.readNext(idleft)) & (readright = rightcursor.readNext(idright)));

	return readleft == readright;
}

bool CV2PDB::mapTypes()
{
	int typeID = nextUserType;
	unsigned long long off = 0;
	std::vector<FrameInfoData> frames;
	FrameInfoData frame = { FrameInfoData::Normal };
	std::vector<DIECursor> framecursor;
	std::unordered_map<int, byte*> mapTypeToFirstOffset;
	if (debug)
		printf("mapping dwarf types to cv types: 0%%");
	while (off < dbgimg.debug_info_length)
	{
		DIECursor cursor = getCompilationUnitCursor(off);
		if (!useGlobalMod)
		{
			mapTypeToFirstOffset.clear();
			typeID = nextUserType;
		}
		countEntries++;
		DWARF_InfoData id;
		bool readsibl = false;
		while (cursor.readNext(id) || (readsibl = !framecursor.empty()))
		{
			if (readsibl)
			{
				do
				{
					// pop cursor and frame
					cursor = framecursor.back();
					framecursor.pop_back();
					frame = frames.back();
					frames.pop_back();
				} while (!cursor.readSibling(id) && (readsibl = !framecursor.empty()));

				if (readsibl) // read success
					readsibl = false;
				else		  // no more cursors to read from
					break;
			}
			//printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
			//    (unsigned char*)cu + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
			switch (id.tag)
			{
			case DW_TAG_base_type:
			case DW_TAG_class_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_interface_type:
			case DW_TAG_enumeration_type:
			{
				// check for identical mapped type (remove duplicates)
				// as long as all modules get the same type definitions
				int mappedId = -1;
				for (const auto& pair : mapTypeToFirstOffset)
				{
					if (equalDWARFTypes(id.entryPtr, pair.second))
					{
						mappedId = pair.first;
						break;
					}
				}
				if (mappedId == -1)
				{
					mapTypeToFirstOffset.insert(std::make_pair(typeID, id.entryPtr));
					goto addNewMapping;
				}
				mapOffsetToType.insert(std::make_pair(id.entryPtr, mappedId));
				mapOffsetToUdtType.insert(std::make_pair(id.entryPtr, mappedId));
			}	break;

			case DW_TAG_subprogram:
			case DW_TAG_inlined_subroutine:
			{
				framecursor.push_back(cursor);
				cursor = framecursor.back().getSubtreeCursor();
				FrameInfoData& outerframe = getNewPrevFrame(frame, frames);
				outerframe.pc = id.pchi;
				frame.type = id.tag == DW_TAG_inlined_subroutine ? FrameInfoData::Inline : FrameInfoData::Normal;
				frame.func = id.pclo;
				frame.id.code_addr = id.pclo;
				frame.pc = id.pclo;
				if (frame.type == FrameInfoData::Normal)
				{
					if (id.frame_base.type == LocListPtr)
						frame.base = findBestFBLoc(dbgimg, cursor.cu, id.frame_base.sec_off.off);
					else {
						frame.base = decodeLocation(id.frame_base, cursor.cu, 0, DW_AT_frame_base);
						if (frame.base.is_abs()) // pointer into location list in .debug_loc? assume CFA
							frame.base = findBestFBLoc(dbgimg, cursor.cu, frame.base.off);
					}
				}
				// fall through
			}
			case DW_TAG_typedef:
			case DW_TAG_pointer_type:
			case DW_TAG_array_type:
			case DW_TAG_const_type:
			case DW_TAG_reference_type:

			case DW_TAG_subroutine_type:

			case DW_TAG_string_type:
			case DW_TAG_ptr_to_member_type:
			case DW_TAG_set_type:
			case DW_TAG_subrange_type:
			case DW_TAG_file_type:
			case DW_TAG_packed_type:
			case DW_TAG_thrown_type:
			case DW_TAG_volatile_type:
			case DW_TAG_restrict_type: // DWARF3
			case DW_TAG_unspecified_type:
			case DW_TAG_mutable_type: // withdrawn
			case DW_TAG_shared_type:
			case DW_TAG_rvalue_reference_type:
			addNewMapping:
				mapOffsetToType.insert(std::make_pair(id.entryPtr, typeID));
				mapOffsetToUdtType.insert(std::make_pair(id.entryPtr, typeID));
				typeID++;
				break;
			case DW_TAG_GNU_call_site:
				addDWARFCallSite(id, cursor.cu, cursor, &frame);
				break;
			}
		}

		if (!useGlobalMod)
			nextDwarfTypeOfModule.push_back(typeID);
		assert(framecursor.empty() && frames.empty());
		off += cursor.cu.header->getLength();
		if (debug)
			printf("\rmapping dwarf types to cv types: %lld%%", (off * 100) / dbgimg.debug_info_length);
	}

	if (useGlobalMod)
		nextDwarfType = typeID;
	return true;
}

bool CV2PDB::createTypes()
{
	int typeID = nextGlobalType;
	const int pointerAttr = img.isX64() ? CV_PTR_size(8) | CV_PTR_64 : CV_PTR_size(4) | CV_PTR_NEAR32;
	int imod = 0;

	std::list<DIECursor> parentcursor;
	unsigned long long off = 0;
	if (debug)
		printf("creating types in pdb: 0%%");
	while (off < dbgimg.debug_info_length)
	{
		DIECursor cursor = getCompilationUnitCursor(off);
		const CompilationUnitData& cu = cursor.cu;
		if (!useGlobalMod)
		{
			if (!addDWARFModule(imod, cu, true))
				return false;
			typeID = nextUserType = nextGlobalType;
			nextDwarfType = nextDwarfTypeOfModule[imod];
			mapCountToVTShapeType.clear();
		}
		DWARF_InfoData id;
		bool readsibl = false;
		while (cursor.readNext(id) || (readsibl = !parentcursor.empty()))
		{
			if (readsibl)
			{
				do
				{
					// pop cursor and frame
					cursor = parentcursor.back();
					parentcursor.pop_back();
				} while (!cursor.readSibling(id) && (readsibl = !parentcursor.empty()));

				if (readsibl) // read success
					readsibl = false;
				else		  // no more cursors to read from
					break;
			}

			//printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
			//    (unsigned char*)cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);

			int cvtype = -1;
			switch (id.tag)
			{
			case DW_TAG_base_type:
				if (typeID == getTypeByDWARFPtr(cu, id.entryPtr))
					cvtype = addDWARFBasicType(id.name, id.encoding, (int)getDWARFByteSize(id, cu));
				break;
			case DW_TAG_typedef:
				cvtype = appendModifierType(getTypeByDWARFPtr(cu, id.type), 0);
				break;
			case DW_TAG_pointer_type:
				cvtype = appendPointerType(getTypeByDWARFPtr(cu, id.type), pointerAttr);
				break;
			case DW_TAG_array_type:
				cvtype = addDWARFArray(id, cursor.getSubtreeCursor());
				break;
			case DW_TAG_const_type:
				cvtype = appendModifierType(getTypeByDWARFPtr(cu, id.type), CV_modifier_const);
				break;
			case DW_TAG_volatile_type:
				cvtype = appendModifierType(getTypeByDWARFPtr(cu, id.type), CV_modifier_volatile);
				break;
			case DW_TAG_reference_type:
				cvtype = appendPointerType(getTypeByDWARFPtr(cu, id.type), pointerAttr | CV_PTR_MODE_REF);
				break;
			case DW_TAG_rvalue_reference_type:
				cvtype = appendPointerType(getTypeByDWARFPtr(cu, id.type), pointerAttr | CV_PTR_MODE_RVREF);
				break;

			case DW_TAG_class_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_interface_type:
			case DW_TAG_enumeration_type:
				parentcursor.push_back(cursor);
				cursor = parentcursor.back().getSubtreeCursor();
				if (typeID == getTypeByDWARFPtr(cu, id.entryPtr))
				{
					if (id.tag != DW_TAG_enumeration_type)
						cvtype = addDWARFStructure(id, cu, cursor);
					else
						cvtype = addDWARFEnum(id, cu, cursor);
				}
				break;

			case DW_TAG_subrange_type:
				if (typeID == getTypeByDWARFPtr(cu, id.entryPtr))
					cvtype = appendModifierType(getDWARFSubrangeType(id, cu), 0);
				break;

			case DW_TAG_string_type:
			case DW_TAG_ptr_to_member_type:
			case DW_TAG_set_type:
			case DW_TAG_file_type:
			case DW_TAG_packed_type:
			case DW_TAG_thrown_type:
			case DW_TAG_restrict_type: // DWARF3
			case DW_TAG_unspecified_type:
			case DW_TAG_mutable_type: // withdrawn
			case DW_TAG_shared_type:
				cvtype = appendPointerType(T_INT4, pointerAttr);
				break;

			case DW_TAG_subroutine_type:
			case DW_TAG_subprogram:
			case DW_TAG_inlined_subroutine:
				cvtype = addDWARFSubroutineType(id, cu, cursor.getSubtreeCursor(),
					!parentcursor.empty() ? getTypeByDWARFPtr(cu, parentcursor.back().lastptr) : 0,
					id.tag == DW_TAG_inlined_subroutine);
				break;

				// following are evaluated at special places, so ignore them here
			case DW_TAG_variable:
			case DW_TAG_formal_parameter:
			case DW_TAG_unspecified_parameters:
			case DW_TAG_label:
			case DW_TAG_lexical_block:
			case DW_TAG_GNU_call_site:
			case DW_TAG_GNU_call_site_parameter:
			case DW_TAG_inheritance:
			case DW_TAG_member:
			case DW_TAG_enumerator:
			case DW_TAG_template_type_parameter:
			case DW_TAG_template_value_parameter:
			case DW_TAG_GNU_template_parameter_pack:
			case DW_TAG_dwarf_procedure: // only referenced by DW_OP_call* expressions
				break;
				//TODO: use these tags for symbol/type definitions
			case DW_TAG_namespace:
			case DW_TAG_imported_declaration:
			case DW_TAG_imported_module:
			case DW_TAG_imported_unit:
				break;
			default:
				printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
					(unsigned char*)cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
				break;
			}

			if (cvtype >= 0)
			{
				assert(cvtype == typeID); typeID++;
				assert(mapOffsetToType[id.entryPtr] == cvtype);
			}
		}

		assert(parentcursor.empty());

		if (!useGlobalMod && (cbUserTypes || cbDwarfTypes))
		{
			byte* data = new byte[cbUserTypes + cbDwarfTypes];
			modTypes[imod] = data;
			cbModTypes[imod] = cbUserTypes + cbDwarfTypes;
			int dataoff = 0;
			if (cbUserTypes)
			{
				memcpy(data + dataoff, userTypes, cbUserTypes);
				dataoff += cbUserTypes;
				memset(userTypes, 0, cbUserTypes);
				cbUserTypes = 0;
			}
			if (cbDwarfTypes)
			{
				memcpy(data + dataoff, dwarfTypes, cbDwarfTypes);
				dataoff += cbDwarfTypes;
				memset(dwarfTypes, 0, cbDwarfTypes);
				cbDwarfTypes = 0;
			}
		}
		++imod;
		off += cu.header->getLength();
		if (debug)
			printf("\rcreating types in pdb: %lld%%", (off * 100) / dbgimg.debug_info_length);
	}

	return true;
}

bool CV2PDB::addDWARFSymbols()
{
	mspdb::Mod* mod;
	int imod = 0;

	if (useGlobalMod)
	{
		mod = globalMod();
		checkModSymbolAlloc(100);
		unsigned int len;
		const unsigned int align = 4;
		// SSEARCH
		codeview_symbol* cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
		cvs->ssearch_v1.id = S_SSEARCH_V1;
		cvs->ssearch_v1.segment = img.codeSegment + 1;
		cvs->ssearch_v1.offset = 0;
		len = sizeof(cvs->ssearch_v1);
		for (; len & (align - 1); len++)
			modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
		cvs->ssearch_v1.len = len - 2;
		cbModSymbols += len;

		// COMPILAND
		cvs = (codeview_symbol*)(modSymbols + cbModSymbols);
		cvs->compiland_v1.id = S_COMPILAND_V1;
		cvs->compiland_v1.language = CV_CFL_CXX; // C++
		cvs->compiland_v1.flags = 0x80; // ? (CV_CFL_AMBDATA)
		cvs->compiland_v1.machine = img.isX64() ? CV_CFL_X64 : CV_CFL_PENTIUMII; //0x06: Pentium Pro/II, 0xd0: x64
		len = sizeof(cvs->compiland_v1) - sizeof(cvs->compiland_v1.p_version);
		len += c2p("cv2pdb", cvs->compiland_v1.p_version);
		for (; len & (align - 1); len++)
			modSymbols[cbModSymbols + len] = 0xf4 - (len & 3);
		cvs->compiland_v1.len = len - 2;
		cbModSymbols += len;

#if 0
		// define one proc over everything
		int s = codeSegment;
		int pclo = 0; // img.getImageBase() + img.getSection(s).VirtualAddress;
		int pchi = pclo + img.getSection(s).Misc.VirtualSize;
		addDWARFProc("procall", pclo, pchi, 0, 0, 0);
#endif
	}

	unsigned long long off = 0;
	if (debug)
		printf("adding symbols to pdb: 0%%");
	while (off < dbgimg.debug_info_length)
	{
		DIECursor cursor = getCompilationUnitCursor(off);
		const CompilationUnitData& cu = cursor.cu;
		if (!useGlobalMod)
		{
			if (!addDWARFModule(imod, cu, false))
				return false;
			mod = modules[imod];
			++imod;
		}
		DWARF_InfoData id;
		while (cursor.readNext(id))
		{
			//printf("0x%08x, level = %d, id.code = %d, id.tag = %d\n",
			//    (unsigned char*)cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);

			switch (id.tag)
			{
			case DW_TAG_base_type:
				if (useTypedefEnum)
					addUdtSymbol(getTypeByDWARFPtr(cu, id.entryPtr, true), id.name, useGlobalMod);
				break;
			case DW_TAG_typedef:
			case DW_TAG_class_type:
			case DW_TAG_structure_type:
			case DW_TAG_union_type:
			case DW_TAG_interface_type:
			case DW_TAG_enumeration_type:
			case DW_TAG_subrange_type:
				if (!id.name)
					id.name = createUniqueNameForUnnamedType(id.tag, getTypeByDWARFPtr(cu, id.entryPtr), id.decl_file);
				addUdtSymbol(getTypeByDWARFPtr(cu, id.entryPtr, true), id.name, useGlobalMod);
				break;

			case DW_TAG_subprogram:
			{
				if (!id.pchi && id.ranges.type != Invalid)
				{
					pcRange_t bounds;
					if (decodeRanges(id.ranges, &bounds, cu, NULL))
					{
						id.pclo = bounds.pclo;
						id.pchi = bounds.pchi;
					}
				}
				if (id.pclo && id.pchi)
				{
					char namebuf[kMaxNameLen];
					if (!id.name)
					{
						if (id.linkage_name)
						{
							id.name = demangleSymbols &&
								cpp_demangle(id.linkage_name, namebuf, kMaxNameLen, true) ? namebuf : id.linkage_name;
						}
						else
						{
							//TODO: how to handle this case?
							assert(false);
							break;
						}
					}
					addDWARFProc(mod, id, cu, cursor.getSubtreeCursor());
					if (id.external) {
						int rc = mod->AddPublic2(id.name, img.codeSegment + 1, (unsigned long)(id.pclo - codeSegOff), CV_PUBSYMFLAGS_cvpsfFunction);
					}
					cursor.gotoSibling();
				}
			}	break;

			case DW_TAG_variable:
				if (id.name)
				{
					int seg = -1;
					unsigned long segOff;
					if (id.location.type == Invalid)
					{
						if (id.external && id.linkage_name)
						{
							seg = img.findSymbol(id.linkage_name, segOff);
						}
					}
					else if (id.location.type == LocListPtr)
					{
#ifdef _DEBUG
						for (const auto& loc : decodeLocationList(id.location, cu))
						{
							assert(!loc.second.is_abs());
						}
#endif // _DEBUG
					}
					else
					{
						Location loc = decodeLocation(id.location, cu);
						if (loc.is_abs())
						{
							seg = img.findSection(loc.off);
							if (seg >= 0)
								segOff = (unsigned long)(loc.off - img.getSectionVMA(seg));
						}
					}
					if (seg >= 0)
					{
						int type = getTypeByDWARFPtr(cu, id.type, true);
						appendGlobalVar(id.name, type, seg + 1, segOff);
						int rc = mod->AddPublic2(id.name, seg + 1, segOff, CV_PUBSYMFLAGS_cvpsfNone);
					}
				}
				break;

			case DW_TAG_label:
				if (id.name && id.pclo)
					appendLabel(id.name, id.pclo);
				break;

			case DW_TAG_formal_parameter:
			case DW_TAG_unspecified_parameters:
			case DW_TAG_lexical_block:
			case DW_TAG_inlined_subroutine:
			case DW_TAG_GNU_call_site:
			case DW_TAG_GNU_call_site_parameter:
			case DW_TAG_inheritance:
			case DW_TAG_member:
			case DW_TAG_enumerator:
			case DW_TAG_template_type_parameter:
			case DW_TAG_template_value_parameter:
			case DW_TAG_GNU_template_parameter_pack:
				break;
				//TODO: use these tags for symbol/type definitions
			case DW_TAG_namespace:
			case DW_TAG_imported_declaration:
			case DW_TAG_imported_module:
			case DW_TAG_imported_unit:
				break;
			default:
				if (!dwarf_preprocess_die(id.tag))
					printf("\r" __FUNCTION__ ": 0x%08x, level = %d, id.code = %d, id.tag = %d\n",
					(unsigned char*)cu.header + id.entryOff - (unsigned char*)dbgimg.debug_info, cursor.level, id.code, id.tag);
				break;
			}
		}


		if (!useGlobalMod && (cbModSymbols || cbUdtSymbols))
		{
			if (!addStringTable(mod))
				return false;
			if (cbModStringTable)
			{
				memset(modStringTable, 0, cbModStringTable);
				cbModStringTable = 0;
			}
			if (!addFPOData(mod))
				return false;
			if (cbModFPOData)
			{
				memset(modFPOData, 0, cbModFPOData);
				cbModFPOData = 0;
			}
			if (!addSymbols(mod, modSymbols, cbModSymbols, true))
				return false;
			if (cbModSymbols)
			{
				memset(modSymbols, 0, cbModSymbols);
				cbModSymbols = 0;
			}
			if (cbUdtSymbols)
			{
				memset(udtSymbols, 0, cbUdtSymbols);
				cbUdtSymbols = 0;
			}
		}

		off += cu.header->getLength();
		if (debug)
			printf("\radding symbols to pdb: %lld%%", (off * 100) / dbgimg.debug_info_length);
	}

	if (useGlobalMod)
	{
		addSymbols(mod, modSymbols, cbModSymbols, true);
		memset(modSymbols, 0, cbModSymbols);
		cbModSymbols = 0;
	}

	return true;
}

bool CV2PDB::createDWARFModules()
{
	if (!dbgimg.debug_info)
		return setError("no .debug_info section found");

	codeSegOff = img.getSectionVMA(img.codeSegment);
	codeSegOffRVA = (long)(codeSegOff - img.getImageBase());
	int nsec;
	int rsdslen = sizeof(*rsds) + strlen((char*)(rsds + 1)) + 1;
	if (!img.replaceDebugSection(rsds, rsdslen, false, true, &nsec))
		return setError(img.getLastError());

	for (int s = 0; s < nsec - 1; s++)
	{
		const IMAGE_SECTION_HEADER& sec = img.getSection(s);
		unsigned short flags = CV_SEGDESCFLAGS_reserved6 | CV_SEGDESCFLAGS_reserved1;
		if (sec.Characteristics&IMAGE_SCN_MEM_READ)
			flags |= CV_SEGDESCFLAGS_read;
		if (sec.Characteristics&IMAGE_SCN_MEM_EXECUTE)
			flags |= CV_SEGDESCFLAGS_execute;
		if (sec.Characteristics&IMAGE_SCN_MEM_WRITE)
			flags |= CV_SEGDESCFLAGS_write;
		int rc = dbi->AddSec(s + 1, flags, 0, sec.Misc.VirtualSize);
		if (rc <= 0)
			return setError("cannot add section");
	}

	// add debug section to the end
	int rc = dbi->AddSec(nsec, (unsigned short)(CV_SEGDESCFLAGS_write | IMAGE_SCN_MEM_READ |
		CV_SEGDESCFLAGS_reserved6 | CV_SEGDESCFLAGS_reserved1), 0,
		rsdslen + sizeof(IMAGE_DEBUG_DIRECTORY));
	if (rc <= 0)
		return setError("cannot add section");

#if FULL_CONTRIB
	mspdb::Mod* mod = globalMod();
	// we use a single global module, so we can simply add the whole text segment
	int segFlags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE |
		IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_CNT_CODE;
	//int segFlags = IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_8BYTES |
	//	IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_CNT_INITIALIZED_DATA; // TODO
	//int segFlags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE |
	//	IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_CNT_CODE; // TODO
	int s = img.codeSegment;
	int pclo = 0; // img.getImageBase() + img.getSection(s).VirtualAddress;
	int pchi = pclo + img.getSection(s).Misc.VirtualSize;
	int rc = mod->AddSecContrib(s + 1, pclo, pchi - pclo, segFlags);
	if (rc <= 0)
		return setError("cannot add section contribution to module");
#endif

	checkUserTypeAlloc();

	createEmptyFieldListType();
	createEmptyArgListType();
	if (Dversion > 0)
	{
		appendComplex(T_CPLX32, T_REAL32, 4, "cfloat");
		appendComplex(T_CPLX64, T_REAL64, 8, "cdouble");
		appendComplex(T_CPLX80, T_REAL80, 12, "creal");
	}

	checkGlobalTypeAlloc(cbUserTypes + sizeof(DWORD));
	*(DWORD*)globalTypes = CV_SIGNATURE_C13;
	cbGlobalTypes = sizeof(DWORD);

	memcpy(globalTypes + cbGlobalTypes, userTypes, cbUserTypes);
	memset(userTypes, 0, cbUserTypes);
	cbGlobalTypes += cbUserTypes;
	cbUserTypes = 0;
	nextGlobalType = nextUserType;

	DIECursor::setContext(&img, &dbgimg);

	countEntries = 0;
	if (!mapTypes())
		return false;

	modules = new mspdb::Mod*[countEntries];
	modTypes = new byte*[countEntries];
	cbModTypes = new int[countEntries];
	memset(modules, 0, countEntries * sizeof(*modules));
	memset(modTypes, 0, countEntries * sizeof(*modTypes));
	memset(cbModTypes, 0, countEntries * sizeof(*cbModTypes));
	if (!createTypes())
		return false;

	/*
	if(!iterateDWARFDebugInfo(kOpMapTypes))
		return false;
	if(!iterateDWARFDebugInfo(kOpCreateTypes))
		return false;
	*/

#if 0
	for (int m = 0; m < countEntries; m++)
	{
		mspdb::Mod* mod = globalMod();
}
#endif

	return true;
	}

bool CV2PDB::addDWARFLines()
{
	if (!dbgimg.debug_line)
		return setError("no .debug_line section found");

	int imod = 0;
	unsigned long long off = 0;
	while (off < dbgimg.debug_info_length)
	{
		DIECursor cursor = getCompilationUnitCursor(off);
		if (!interpretDWARFLines(cursor.cu, dbgimg, useGlobalMod ? globalMod() : modules[imod]))
			return setError("cannot add line number info to module");
		++imod;

		off += cursor.cu.header->getLength();
	}

	return true;
}

bool CV2PDB::addDWARFPublics()
{
	mspdb::Mod* mod;
	int imod;
	ImportSymbol sym;
	std::vector<CompilationUnitData> importCUs;
	if (useGlobalMod)
	{
		mod = globalMod();

#if 0
		int type = 0;
		int rc = mod->AddPublic2("public_all", img.codeSegment + 1, 0, CV_PUBSYMFLAGS_cvpsfNone);
		if (rc <= 0)
			return setError("cannot add public");
#endif
	}
	else
	{
		imod = countEntries;
		while (img.getNextImportSymbol(sym))
		{
			if (sym.sec >= 0)
			{
				CompilationUnitData* cu = importCUs.empty() ? NULL : &importCUs.back();
				if (!cu || cu->name != sym.libname)
				{
					importCUs.emplace_back();
					cu = &importCUs.back();
					cu->name = sym.libname;
					++countEntries;
				}
				unsigned long long impoff = sym.off + img.getSectionVMA(sym.sec);
				const DWARF_InfoData* thunkid = getThunkByImportOffset(impoff);
				if (thunkid)
					cu->ranges.push_back({ thunkid->pclo, thunkid->pchi });
				pcRange_t range;
				range.pclo = impoff;
				range.pchi = impoff + (img.isX64() ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
				cu->ranges.push_back(range);
			}
		}
		mspdb::Mod** oldmodules = modules;
		modules = new mspdb::Mod*[countEntries];
		memcpy(modules, oldmodules, imod * sizeof(*modules));
		delete[] oldmodules;
		memset(modules + imod, 0, (countEntries - imod) * sizeof(*modules));
	}

	if (useGlobalMod || countEntries > imod)
	{
		char impname[kMaxNameLen];
		strcpy(impname, "__imp_");

		size_t icu = -1;
		while (img.getNextImportSymbol(sym))
		{
			if (sym.sec >= 0)
			{
				if (!useGlobalMod)
				{
					if (icu == -1 ||
						(icu < importCUs.size() && importCUs[icu].name != sym.libname))
					{
						if (icu != -1 && cbModSymbols)
						{
							addSymbols(mod, modSymbols, cbModSymbols, false);
							memset(modSymbols, 0, cbModSymbols);
							cbModSymbols = 0;
						}

						const CompilationUnitData& cu = importCUs[++icu];
						if (!addDWARFModule(imod, cu, true, true) ||
							!addDWARFModule(imod, cu, false, true))
							return setError("cannot add import module");

						mod = modules[imod++];
					}
				}

				unsigned long long impoff = sym.off + img.getSectionVMA(sym.sec);
				const DWARF_InfoData* thunkid = getThunkByImportOffset(impoff);
				if (thunkid)
				{
					if (!useGlobalMod)
					{
						int len = appendThunk(thunkid->name, { thunkid->pclo, thunkid->pchi });
						appendEnd(cbModSymbols - len);
					}
					int rc = mod->AddPublic2(thunkid->linkage_name, img.codeSegment + 1, (unsigned long)(thunkid->pclo - codeSegOff), CV_PUBSYMFLAGS_cvpsfFunction);
				}
				if (sym.symname)
				{
					strcpy(impname + sizeof("__imp_") - 1, sym.symname);
					int rc = mod->AddPublic2(impname, sym.sec + 1, sym.off, CV_PUBSYMFLAGS_cvpsfNone);
				}
			}
		}

		if (icu != -1 && cbModSymbols)
		{
			addSymbols(mod, modSymbols, cbModSymbols, false);
			memset(modSymbols, 0, cbModSymbols);
			cbModSymbols = 0;
		}
	}

	return true;
}

bool CV2PDB::writeDWARFImage(const TCHAR* opath)
{
	int len = sizeof(*rsds) + strlen((char*)(rsds + 1)) + 1;
	if (!img.replaceDebugSection(rsds, len, false))
		return setError(img.getLastError());

	if (!img.save(opath))
		return setError(img.getLastError());

	return true;
}
