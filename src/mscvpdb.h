/*
 * MS debug information definitions.
 *
 * Copyright (C) 1996 Eric Youngdale
 * Copyright (C) 1999-2000 Ulrich Weigand
 * Copyright (C) 2004 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* MS has stored all its debug information in a set of structures
 * which has been rather consistent across the years (ie you can grasp
 * some continuity, and not so many drastic changes).
 *
 * A bit of history on the various formats
 *      MSVC 1.0        PDB v1 (new format for debug info)
 *      MSVC 2.0        Inclusion in link of debug info (PDB v2)
 *      MSVC 5.0        Types are 24 bits (instead of 16 for <= 4.x)
 *      MSVC x.0        PDB (change in internal streams layout)
 *
 *      .DBG            Contains COFF, FPO and Codeview info
 *      .PDB            New format for debug info (information is
 *                      derived from Codeview information)
 *      VCx0.PDB        x major MSVC number, stores types, while
 *                      <project>.PDB stores symbols.
 *
 * Debug information can either be found in the debug section of a PE
 * module (in something close to a .DBG file), or the debug section
 * can actually refer to an external file, which can be in turn,
 * either a .DBG or .PDB file.
 *
 * Regarding PDB files:
 * -------------------
 * They are implemented as a set of internal files (as a small file
 * system). The file is split into blocks, an internal file is made
 * of a set of blocks. Internal files are accessed through
 * numbers. For example,
 * 1/ is the ROOT (basic information on the file)
 * 2/ is the Symbol information (global symbols, local variables...)
 * 3/ is the Type internal file (each the symbols can have type
 * information associated with it).
 *
 * Over the years, three formats existed for the PDB:
 * - ?? was rather linked to 16 bit code (our support shall be rather
 *   bad)
 * - JG: it's the signature embedded in the file header. This format
 *   has been used in MSVC 2.0 => 5.0.
 * - DS: it's the signature embedded in the file header. It's the
 *   current format supported my MS.
 *
 * Types internal stream
 * ---------------------
 * Types (from the Type internal file) have existed in three flavors
 * (note that those flavors came as historical evolution, but there
 * isn't a one to one link between types evolution and PDB formats'
 * evolutions:
 * - the first flavor (suffixed by V1 in this file), where the types
 *   and subtypes are 16 bit entities; and where strings are in Pascal
 *   format (first char is their length and are not 0 terminated)
 * - the second flavor (suffixed by V2) differs from first flavor with
 *   types and subtypes as 32 bit entities. This forced some
 *   reordering of fields in some types
 * - the third flavor (suffixed by V3) differs from second flavor with
 *   strings stored as C strings (ie are 0 terminated, instead of
 *   length prefixed)
 * The different flavors can coexist in the same file (is this really
 * true ??)
 *
 * For the evolution of types, the need of the second flavor was the
 * number of types to be defined (limited to 0xFFFF, including the C
 * basic types); the need of the third flavor is the increase of
 * symbol size (to be greater than 256), which was likely needed for
 * complex C++ types (nested + templates).
 *
 * It's somehow difficult to represent the layout of those types on
 * disk because:
 * - some integral values are stored as numeric leaf, which size is
 *   variable depending on its value
 *
 * Symbols internal stream
 * -----------------------
 * Here also we find three flavors (that we've suffixed with _V1, _V2
 * and _V3) even if their evolution is closer to the evolution of
 * types, they are not completely linked together.
 */

#include "pshpack1.h"

/* ======================================== *
 *             Type information
 * ======================================== */

struct p_string
{
    unsigned char               namelen;
    char                        name[1];
};

#define CV_SIGNATURE_C6         0L  // Actual signature is >64K
#define CV_SIGNATURE_C7         1L  // First explicit signature
#define CV_SIGNATURE_C11        2L  // C11 (vc5.x) 32-bit types
#define CV_SIGNATURE_C13        4L  // C13 (vc7.x) zero terminated names
#define CV_SIGNATURE_RESERVED   5L  // All signatures from 5 to 64K are reserved

union codeview_type
{
    struct
    {
        unsigned short int      len;
        short int               id;
    } generic;

    struct
    {
        unsigned short int      len;
        short int               id;
        short int               attribute;
        unsigned short int      type;
    } modifier_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        int                     type;
        short int               attribute;
    } modifier_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        short int               attribute;
        unsigned short int      datatype;
    } pointer_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            datatype;
        unsigned int            attribute;
    } pointer_v2;

	struct
	{
		unsigned short int      len;
		short int               id;
		short int               attribute;
		unsigned short int      datatype;
		unsigned short int      pmclass;    // index of containing class for pointer to member
		unsigned short int		pmenum;     // enumeration specifying pm format (CV_pmtype_e)
	} pointer_to_member_v1;

	struct
	{
		unsigned short int      len;
		short int               id;
		unsigned int            datatype;
		unsigned int            attribute;
		unsigned int			pmclass;    // index of containing class for pointer to member
		unsigned short int		pmenum;     // enumeration specifying pm format (CV_pmtype_e)
	} pointer_to_member_v2;

	struct
	{
		unsigned short int      len;
		short int               id;
		short int               attribute;
		unsigned short int      datatype;
		unsigned short int		pointertype;	// type index if CV_PTR_BASE_TYPE
		struct p_string         p_name;			// name of base type
	} pointer_base_type_v1;

	struct
	{
		unsigned short int      len;
		short int               id;
		unsigned int            datatype;
		unsigned int            attribute;
		unsigned int            pointertype;	// type index if CV_PTR_BASE_TYPE
		struct p_string         p_name;			// name of base type
	} pointer_base_type_v2;

	struct
	{
		unsigned short int      len;
		short int               id;
		short int               attribute;
		unsigned short int      datatype;
		unsigned short int		bseg;			// base segment if CV_PTR_BASE_SEG
	} pointer_base_seg_v1;

	struct
	{
		unsigned short int      len;
		short int               id;
		unsigned int            datatype;
		unsigned int            attribute;
		unsigned short int		bseg;			// base segment if CV_PTR_BASE_SEG
	} pointer_base_seg_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      elemtype;
        unsigned short int      idxtype;
        unsigned short int      arrlen;     /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } array_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            elemtype;
        unsigned int            idxtype;
        unsigned short int      arrlen;    /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } array_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            elemtype;
        unsigned int            idxtype;
        unsigned short int      arrlen;    /* numeric leaf */
#if 0
        char                    name[1];
#endif
    } array_v3;

    struct
    {
        unsigned short int      len;
        short int               id;
        short int               n_element;
        unsigned short int      fieldlist;
        short int               property;
        unsigned short int      derived;
        unsigned short int      vshape;
        unsigned short int      structlen;  /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } struct_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        short int               n_element;
        short int               property;
        unsigned int            fieldlist;
        unsigned int            derived;
        unsigned int            vshape;
        unsigned short int      structlen;  /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } struct_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        short int               n_element;
        short int               property;
        unsigned int            fieldlist;
        unsigned int            derived;
        unsigned int            vshape;
        unsigned short int      structlen;  /* numeric leaf */
#if 0
        char                    name[1];
#endif
    } struct_v3;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        unsigned short int      fieldlist;
        short int               property;
        unsigned short int      un_len;     /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } union_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        short int               property;
        unsigned int            fieldlist;
        unsigned short int      un_len;     /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } union_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        short int               property;
        unsigned int            fieldlist;
        unsigned short int      un_len;     /* numeric leaf */
#if 0
        char                    name[1];
#endif
    } union_v3;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        unsigned short int      type;
        unsigned short int      fieldlist;
        short int               property;
        struct p_string         p_name;
    } enumeration_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        short int               property;
        unsigned int            type;
        unsigned int            fieldlist;
        struct p_string         p_name;
    } enumeration_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      count;
        short int               property;
        unsigned int            type;
        unsigned int            fieldlist;
        char                    name[1];
    } enumeration_v3;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      rvtype;
        unsigned char           call;
        unsigned char           attr;
        unsigned short int      params;
        unsigned short int      arglist;
    } procedure_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            rvtype;
        unsigned char           call;
        unsigned char           attr;
        unsigned short int      params;
        unsigned int            arglist;
    } procedure_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short int      rvtype;
        unsigned short int      class_type;
        unsigned short int      this_type;
        unsigned char           call;
        unsigned char           attr;
        unsigned short int      params;
        unsigned short int      arglist;
        unsigned int            this_adjust;
    } mfunction_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            rvtype;
        unsigned int            class_type;
        unsigned                this_type;
        unsigned char           call;
        unsigned char           attr;
        unsigned short          params;
        unsigned int            arglist;
        unsigned int            this_adjust;
    } mfunction_v2;

	struct
	{
		unsigned short int      len;
		short int				id;			// LF_FUNC_ID
		unsigned long			scopeId;    // parent scope of the ID, 0 if global
		unsigned long			type;       // function type
		unsigned char			name[1];
	} funcid_v3;

	struct
	{
		unsigned short int      len;
		short int				id;			// LF_MFUNC_ID
		unsigned long			parentType; // type index of parent
		unsigned long			type;       // function type
		unsigned char			name[1];
	} mfuncid_v3;

	struct
	{
		unsigned short int      len;
		short int				id;			// LF_STRING_ID
		unsigned long			listid;     // ID to list of sub string IDs
		unsigned char			name[1];
	} stringid_v3;

	struct
	{
		unsigned short int      len;
		short int				id;			// LF_UDT_SRC_LINE
		unsigned long			type;       // UDT's type index
		unsigned long			src;        // index to LF_STRING_ID record where source file name is saved
		unsigned long			line;       // line number
	} udt_src_line;

	struct
	{
		unsigned short int      len;
		short int				id;			// LF_UDT_MOD_SRC_LINE
		unsigned long			type;		// UDT's type index
		unsigned long			src;		// index into string table where source file name is saved
		unsigned long			line;		// line number
		unsigned short			imod;		// module that contributes this UDT definition 
	} udt_mod_src_line;
};

union codeview_reftype
{
    struct
    {
        unsigned short int      len;
        short int               id;
    } generic;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned char           list[1];
    } fieldlist;

	struct
	{
		unsigned short int      len;
		short int               id;
		unsigned char           list[1];
	} methodlist;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned char           nbits;
        unsigned char           bitoff;
        unsigned short          type;
    } bitfield_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned int            type;
        unsigned char           nbits;
        unsigned char           bitoff;
    } bitfield_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short          num;
        unsigned short          args[1];
    } arglist_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned                num;
        unsigned                args[1];
    } arglist_v2;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned short          num;
        unsigned short          drvdcls[1];
    } derived_v1;

    struct
    {
        unsigned short int      len;
        short int               id;
        unsigned                num;
        unsigned                drvdcls[1];
    } derived_v2;

	struct
	{
		unsigned short int      len;
		short int               id;
		unsigned short          num;
		unsigned char			desc[1];     // 4 bit (CV_VTS_desc) descriptors
	} vtshape_v1;
};

union codeview_fieldtype
{
    struct
    {
        short int		id;
    } generic;

    struct
    {
        short int          id;
        unsigned short int type;
        short int          attribute;
        unsigned short int offset;     /* numeric leaf */
    } bclass_v1;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       type;
        unsigned short int offset;     /* numeric leaf */
    } bclass_v2;

    struct
    {
        short int          id;
        unsigned short int btype;
        unsigned short int vbtype;
        short int          attribute;
        unsigned short int vbpoff;     /* numeric leaf */
#if 0
        unsigned short int	vboff;      /* numeric leaf */
#endif
    } vbclass_v1;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       btype;
        unsigned int       vbtype;
        unsigned short int vbpoff;     /* numeric leaf */
#if 0
        unsigned short int	vboff;      /* numeric leaf */
#endif
    } vbclass_v2;

    struct
    {
        short int		id;
        short int		attribute;
        unsigned short int	value;     /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } enumerate_v1;

   struct
    {
        short int               id;
        short int               attribute;
        unsigned short int      value;     /* numeric leaf */
#if 0
        char                    name[1];
#endif
    } enumerate_v3;

    struct
    {
        short int          id;
        unsigned short int type;
        struct p_string    p_name;
    } friendfcn_v1;

    struct
    {
        short int          id;
        short int          _pad0;
        unsigned int       type;
        struct p_string    p_name;
    } friendfcn_v2;

    struct
    {
        short int          id;
        unsigned short int type;
        short int          attribute;
        unsigned short int offset;    /* numeric leaf */
#if 0
        struct p_string    p_name;
#endif
    } member_v1;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       type;
        unsigned short int offset;    /* numeric leaf */
#if 0
        struct p_string    p_name;
#endif
    } member_v2;

    struct
    {
        short int               id;
        short int               attribute;
        unsigned int            type;
        unsigned short int      offset; /* numeric leaf */
#if 0
        unsigned char           name[1];
#endif
    }
    member_v3;

    struct
    {
        short int          id;
        unsigned short int type;
        short int          attribute;
        struct p_string    p_name;
    } stmember_v1;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       type;
        struct p_string    p_name;
    } stmember_v2;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int	   type;
        char               name[1];
    } stmember_v3;

    struct
    {
        short int          id;
        short int          count;
        unsigned short int mlist;
        struct p_string    p_name;
    } method_v1;

    struct
    {
        short int          id;
        short int          count;
        unsigned int       mlist;
        struct p_string    p_name;
    } method_v2;

    struct
    {
        short int          id;
        short int          count;
        unsigned int       mlist;
        char               name[1];
    } method_v3;

    struct
    {
        short int          id;
        unsigned short int type;
        struct p_string    p_name;
    } nesttype_v1;

    struct
    {
        short int          id;
        short int          _pad0;
        unsigned int       type;
        struct p_string    p_name;
    } nesttype_v2;

    struct
    {
        short int          id;
        short int          _pad0;
        unsigned int       type;
        char               name[1];
    } nesttype_v3;

    struct
    {
        short int          id;
        unsigned short int type;
    } vfunctab_v1;

    struct
    {
        short int          id;
        short int          _pad0;
        unsigned int       type;
    } vfunctab_v2;

    struct
    {
        short int          id;
        unsigned short int type;
    } friendcls_v1;

    struct
    {
        short int          id;
        short int          _pad0;
        unsigned int       type;
    } friendcls_v2;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned short int type;
        struct p_string    p_name;
    } onemethod_v1;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       type;
        struct p_string    p_name;
    } onemethod_v2;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned int       type;
        char               name[1];
    } onemethod_v3;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned short int type;
        unsigned long       vtab_offset;
        struct p_string    p_name;
    } onemethod_virt_v1;

    struct
    {
        short int		id;
        short int		attribute;
        unsigned int	        type;
        unsigned long	        vtab_offset;
        struct p_string         p_name;
    } onemethod_virt_v2;

    struct
    {
        short int		id;
        short int		attribute;
        unsigned int	        type;
        unsigned long	        vtab_offset;
        char                    name[1];
    } onemethod_virt_v3;

    struct
    {
        short int          id;
        unsigned short int type;
        unsigned int       offset;
    } vfuncoff_v1;

    struct
    {
        short int		id;
        short int		_pad0;
        unsigned int	        type;
        unsigned int	        offset;
    } vfuncoff_v2;

    struct
    {
        short int          id;
        short int          attribute;
        unsigned short int type;
        struct p_string    p_name;
    } nesttypeex_v1;

    struct
    {
        short int		id;
        short int		attribute;
        unsigned int	        type;
        struct p_string         p_name;
    } nesttypeex_v2;

    struct
    {
        short int		id;
        short int		attribute;
        unsigned int	        type;
        struct p_string         p_name;
    } membermodify_v2;

    struct
    {
        short int               id;
        short int               ref;
    } index_v1;

    struct
    {
        short int               id;
        short int               unk;
        unsigned int            ref;
    } index_v2;
};

union codeview_mltype
{
	struct
	{
		short int          attribute;
		unsigned short int type;
	} method_v1;

	struct
	{
		short int          attribute;
		unsigned short	   _pad0;
		unsigned int       type;
	} method_v2;

	struct
	{
		short int          attribute;
		unsigned short int type;
		unsigned long	   vbaseoff;    // offset in vfunctable if intro virtual
	} method_virt_v1;

	struct
	{
		short int          attribute;
		unsigned short	   _pad0;
		unsigned int       type;
		unsigned long	   vbaseoff;    // offset in vfunctable if intro virtual
	} method_virt_v2;
};

/*
 * This covers the basic datatypes that VC++ seems to be using these days.
 * 32 bit mode only.  There are additional numbers for the pointers in 16
 * bit mode.  There are many other types listed in the documents, but these
 * are apparently not used by the compiler, or represent pointer types
 * that are not used.
 *
 * Official MS documentation says that type (< 0x4000, so 12 bits) is made of:
 *        +----------+------+------+----------+------+
 *        |    11    | 10-8 | 7-4  |     3    | 2-0  |
 *        +----------+------+------+----------+------+
 *        | reserved | mode | type | reserved | size |
 *        +----------+------+------+----------+------+
 * In recent PDB files, type 8 exists, and is seen as an HRESULT... So we've
 * added this basic type... as if bit 3 had been integrated into the size field
 */

/* the type number of a built-in type is a 16-bit value specified in the following format:
    bit #   |   11     |   10-8   |   7-4    |    3     |    2-0   |
    field   | reserved |   mode   |   type   | reserved |   size   |

    where
        <type> is one of the following types:
                0x00 Special
                0x01 Signed integral value
                0x02 Unsigned integral value
                0x03 Boolean
                0x04 Real
                0x05 Complex
                0x06 Special2
                0x07 Real int value
                0x08 Reserved
                0x09 Reserved
                0x0a Reserved
                0x0b Reserved
                0x0c Reserved
                0x0d Reserved
                0x0e Reserved
                0x0f Reserved for debugger expression evaluator

        <size> is an enumerated value for each of the types.
                Type = special
                    0x00 No type
                    0x01 Absolute symbol
                    0x02 Segment
                    0x03 Void
                    0x04 Basic 8-byte currency value
                    0x05 Near Basic string
                    0x06 Far Basic string
                    0x07 Untranslated type from previous Microsoft symbol formats
                Type = signed/unsigned integral and Boolean values
                    0x00 1 byte
                    0x01 2 byte
                    0x02 4 byte
                    0x03 8 byte
                    0x04 Reserved
                    0x05 Reserved
                    0x06 Reserved
                    0x07 Reserved
                Type = real and complex
                    0x00 32 bit
                    0x01 64 bit
                    0x02 80 bit
                    0x03 128 bit
                    0x04 48 bit
                    0x05 Reserved
                    0x06 Reserved
                    0x07 Reserved
                Type = special2
                    0x00 Bit
                    0x01 Pascal CHAR
                Type = Real int
                    0x00 Char
                    0x01 Wide character
                    0x02 2-byte signed integer
                    0x03 2-byte unsigned integer
                    0x04 4-byte signed integer
                    0x05 4-byte unsigned integer
                    0x06 8-byte signed integer
                    0x07 8-byte unsigned integer

            <mode> is the pointer mode:
                0x00 Direct; not a pointer
                0x01 Near pointer
                0x02 Far pointer
                0x03 Huge pointer
                0x04 32-bit near pointer
                0x05 32-bit far pointer
                0x06 64-bit near pointer
                0x07 Reserved
*/

/* basic types */
#define T_NOTYPE            0x0000  /* Notype */
#define T_ABS               0x0001  /* Abs */
#define T_SEGMENT           0x0002  /* segment type */
#define T_VOID              0x0003  /* Void */
#define T_CURRENCY          0x0004  /* basic 8-byte currency value */
#define T_NBASICSTR         0x0005  /* near basic string */
#define T_FBASICSTR         0x0006  /* far basic string */
#define T_NOTTRANS          0x0007  /* untranslated type record from MS symbol format */
#define T_HRESULT           0x0008  /* HRESULT - or error code ??? */
#define T_CHAR              0x0010  /* signed char */
#define T_SHORT             0x0011  /* short */
#define T_LONG              0x0012  /* long */
#define T_QUAD              0x0013  /* long long */
#define T_UCHAR             0x0020  /* unsigned  char */
#define T_USHORT            0x0021  /* unsigned short */
#define T_ULONG             0x0022  /* unsigned long */
#define T_UQUAD             0x0023  /* unsigned long long */
#define T_BOOL08            0x0030  /* 8-bit boolean */
#define T_BOOL16            0x0031  /* 16-bit boolean */
#define T_BOOL32            0x0032  /* 32-bit boolean */
#define T_BOOL64            0x0033  /* 64-bit boolean */
#define T_REAL32            0x0040  /* float */
#define T_REAL64            0x0041  /* double */
#define T_REAL80            0x0042  /* 80-bit real */
#define T_REAL128           0x0043  /* 128-bit real */
#define T_REAL48            0x0044  /* 48-bit real */
#define T_CPLX32            0x0050  /* 32-bit complex number */
#define T_CPLX64            0x0051  /* 64-bit complex number */
#define T_CPLX80            0x0052  /* 80-bit complex number */
#define T_CPLX128           0x0053  /* 128-bit complex number */
#define T_BIT               0x0060  /* bit */
#define T_PASCHAR           0x0061  /* pascal CHAR */
#define T_RCHAR             0x0070  /* real char */
#define T_WCHAR             0x0071  /* wide char */
#define T_INT2              0x0072  /* real 16-bit signed int */
#define T_UINT2             0x0073  /* real 16-bit unsigned int */
#define T_INT4              0x0074  /* int */
#define T_UINT4             0x0075  /* unsigned int */
#define T_INT8              0x0076  /* 64-bit signed int */
#define T_UINT8             0x0077  /* 64-bit unsigned int */


/* near pointers to basic types */
#define T_PVOID             0x0103  /* near pointer to void */
#define T_PCHAR             0x0110  /* Near pointer to 8-bit signed */
#define T_PSHORT            0x0111  /* Near pointer to 16-bit signed */
#define T_PLONG             0x0112  /* Near pointer to 32-bit signed */
#define T_PQUAD             0x0113  /* Near pointer to 64-bit signed */
#define T_PUCHAR            0x0120  /* Near pointer to 8-bit unsigned */
#define T_PUSHORT           0x0121  /* Near pointer to 16-bit unsigned */
#define T_PULONG            0x0122  /* Near pointer to 32-bit unsigned */
#define T_PUQUAD            0x0123  /* Near pointer to 64-bit unsigned */
#define T_PBOOL08           0x0130  /* Near pointer to 8-bit Boolean */
#define T_PBOOL16           0x0131  /* Near pointer to 16-bit Boolean */
#define T_PBOOL32           0x0132  /* Near pointer to 32-bit Boolean */
#define T_PBOOL64           0x0133  /* Near pointer to 64-bit Boolean */
#define T_PREAL32           0x0140  /* Near pointer to 32-bit real */
#define T_PREAL64           0x0141  /* Near pointer to 64-bit real */
#define T_PREAL80           0x0142  /* Near pointer to 80-bit real */
#define T_PREAL128          0x0143  /* Near pointer to 128-bit real */
#define T_PREAL48           0x0144  /* Near pointer to 48-bit real */
#define T_PCPLX32           0x0150  /* Near pointer to 32-bit complex */
#define T_PCPLX64           0x0151  /* Near pointer to 64-bit complex */
#define T_PCPLX80           0x0152  /* Near pointer to 80-bit complex */
#define T_PCPLX128          0x0153  /* Near pointer to 128-bit complex */
#define T_PRCHAR            0x0170  /* Near pointer to a real char */
#define T_PWCHAR            0x0171  /* Near pointer to a wide char */
#define T_PINT2             0x0172  /* Near pointer to 16-bit signed int */
#define T_PUINT2            0x0173  /* Near pointer to 16-bit unsigned int */
#define T_PINT4             0x0174  /* Near pointer to 32-bit signed int */
#define T_PUINT4            0x0175  /* Near pointer to 32-bit unsigned int */
#define T_PINT8             0x0176  /* Near pointer to 64-bit signed int */
#define T_PUINT8            0x0177  /* Near pointer to 64-bit unsigned int */


/* far pointers to basic types */
#define T_PFVOID            0x0203  /* Far pointer to void */
#define T_PFCHAR            0x0210  /* Far pointer to 8-bit signed */
#define T_PFSHORT           0x0211  /* Far pointer to 16-bit signed */
#define T_PFLONG            0x0212  /* Far pointer to 32-bit signed */
#define T_PFQUAD            0x0213  /* Far pointer to 64-bit signed */
#define T_PFUCHAR           0x0220  /* Far pointer to 8-bit unsigned */
#define T_PFUSHORT          0x0221  /* Far pointer to 16-bit unsigned */
#define T_PFULONG           0x0222  /* Far pointer to 32-bit unsigned */
#define T_PFUQUAD           0x0223  /* Far pointer to 64-bit unsigned */
#define T_PFBOOL08          0x0230  /* Far pointer to 8-bit Boolean */
#define T_PFBOOL16          0x0231  /* Far pointer to 16-bit Boolean */
#define T_PFBOOL32          0x0232  /* Far pointer to 32-bit Boolean */
#define T_PFBOOL64          0x0233  /* Far pointer to 64-bit Boolean */
#define T_PFREAL32          0x0240  /* Far pointer to 32-bit real */
#define T_PFREAL64          0x0241  /* Far pointer to 64-bit real */
#define T_PFREAL80          0x0242  /* Far pointer to 80-bit real */
#define T_PFREAL128         0x0243  /* Far pointer to 128-bit real */
#define T_PFREAL48          0x0244  /* Far pointer to 48-bit real */
#define T_PFCPLX32          0x0250  /* Far pointer to 32-bit complex */
#define T_PFCPLX64          0x0251  /* Far pointer to 64-bit complex */
#define T_PFCPLX80          0x0252  /* Far pointer to 80-bit complex */
#define T_PFCPLX128         0x0253  /* Far pointer to 128-bit complex */
#define T_PFRCHAR           0x0270  /* Far pointer to a real char */
#define T_PFWCHAR           0x0271  /* Far pointer to a wide char */
#define T_PFINT2            0x0272  /* Far pointer to 16-bit signed int */
#define T_PFUINT2           0x0273  /* Far pointer to 16-bit unsigned int */
#define T_PFINT4            0x0274  /* Far pointer to 32-bit signed int */
#define T_PFUINT4           0x0275  /* Far pointer to 32-bit unsigned int */
#define T_PFINT8            0x0276  /* Far pointer to 64-bit signed int */
#define T_PFUINT8           0x0277  /* Far pointer to 64-bit unsigned int */


/* huge pointers to basic types */
#define T_PHVOID            0x0303  /* Huge pointer to void */
#define T_PHCHAR            0x0310  /* Huge pointer to 8-bit signed */
#define T_PHSHORT           0x0311  /* Huge pointer to 16-bit signed */
#define T_PHLONG            0x0312  /* Huge pointer to 32-bit signed */
#define T_PHQUAD            0x0313  /* Huge pointer to 64-bit signed */
#define T_PHUCHAR           0x0320  /* Huge pointer to 8-bit unsigned */
#define T_PHUSHORT          0x0321  /* Huge pointer to 16-bit unsigned */
#define T_PHULONG           0x0322  /* Huge pointer to 32-bit unsigned */
#define T_PHUQUAD           0x0323  /* Huge pointer to 64-bit unsigned */
#define T_PHBOOL08          0x0330  /* Huge pointer to 8-bit Boolean */
#define T_PHBOOL16          0x0331  /* Huge pointer to 16-bit Boolean */
#define T_PHBOOL32          0x0332  /* Huge pointer to 32-bit Boolean */
#define T_PHBOOL64          0x0333  /* Huge pointer to 64-bit Boolean */
#define T_PHREAL32          0x0340  /* Huge pointer to 32-bit real */
#define T_PHREAL64          0x0341  /* Huge pointer to 64-bit real */
#define T_PHREAL80          0x0342  /* Huge pointer to 80-bit real */
#define T_PHREAL128         0x0343  /* Huge pointer to 128-bit real */
#define T_PHREAL48          0x0344  /* Huge pointer to 48-bit real */
#define T_PHCPLX32          0x0350  /* Huge pointer to 32-bit complex */
#define T_PHCPLX64          0x0351  /* Huge pointer to 64-bit complex */
#define T_PHCPLX80          0x0352  /* Huge pointer to 80-bit complex */
#define T_PHCPLX128         0x0353  /* Huge pointer to 128-bit real */
#define T_PHRCHAR           0x0370  /* Huge pointer to a real char */
#define T_PHWCHAR           0x0371  /* Huge pointer to a wide char */
#define T_PHINT2            0x0372  /* Huge pointer to 16-bit signed int */
#define T_PHUINT2           0x0373  /* Huge pointer to 16-bit unsigned int */
#define T_PHINT4            0x0374  /* Huge pointer to 32-bit signed int */
#define T_PHUINT4           0x0375  /* Huge pointer to 32-bit unsigned int */
#define T_PHINT8            0x0376  /* Huge pointer to 64-bit signed int */
#define T_PHUINT8           0x0377  /* Huge pointer to 64-bit unsigned int */


/* 32-bit near pointers to basic types */
#define T_32PVOID           0x0403  /* 32-bit near pointer to void */
#define T_32PHRESULT        0x0408  /* 16:32 near pointer to HRESULT - or error code ??? */
#define T_32PCHAR           0x0410  /* 16:32 near pointer to 8-bit signed */
#define T_32PSHORT          0x0411  /* 16:32 near pointer to 16-bit signed */
#define T_32PLONG           0x0412  /* 16:32 near pointer to 32-bit signed */
#define T_32PQUAD           0x0413  /* 16:32 near pointer to 64-bit signed */
#define T_32PUCHAR          0x0420  /* 16:32 near pointer to 8-bit unsigned */
#define T_32PUSHORT         0x0421  /* 16:32 near pointer to 16-bit unsigned */
#define T_32PULONG          0x0422  /* 16:32 near pointer to 32-bit unsigned */
#define T_32PUQUAD          0x0423  /* 16:32 near pointer to 64-bit unsigned */
#define T_32PBOOL08         0x0430  /* 16:32 near pointer to 8-bit Boolean */
#define T_32PBOOL16         0x0431  /* 16:32 near pointer to 16-bit Boolean */
#define T_32PBOOL32         0x0432  /* 16:32 near pointer to 32-bit Boolean */
#define T_32PBOOL64         0x0433  /* 16:32 near pointer to 64-bit Boolean */
#define T_32PREAL32         0x0440  /* 16:32 near pointer to 32-bit real */
#define T_32PREAL64         0x0441  /* 16:32 near pointer to 64-bit real */
#define T_32PREAL80         0x0442  /* 16:32 near pointer to 80-bit real */
#define T_32PREAL128        0x0443  /* 16:32 near pointer to 128-bit real */
#define T_32PREAL48         0x0444  /* 16:32 near pointer to 48-bit real */
#define T_32PCPLX32         0x0450  /* 16:32 near pointer to 32-bit complex */
#define T_32PCPLX64         0x0451  /* 16:32 near pointer to 64-bit complex */
#define T_32PCPLX80         0x0452  /* 16:32 near pointer to 80-bit complex */
#define T_32PCPLX128        0x0453  /* 16:32 near pointer to 128-bit complex */
#define T_32PRCHAR          0x0470  /* 16:32 near pointer to a real char */
#define T_32PWCHAR          0x0471  /* 16:32 near pointer to a wide char */
#define T_32PINT2           0x0472  /* 16:32 near pointer to 16-bit signed int */
#define T_32PUINT2          0x0473  /* 16:32 near pointer to 16-bit unsigned int */
#define T_32PINT4           0x0474  /* 16:32 near pointer to 32-bit signed int */
#define T_32PUINT4          0x0475  /* 16:32 near pointer to 32-bit unsigned int */
#define T_32PINT8           0x0476  /* 16:32 near pointer to 64-bit signed int */
#define T_32PUINT8          0x0477  /* 16:32 near pointer to 64-bit unsigned int */


/* 32-bit far pointers to basic types */
#define T_32PFVOID          0x0503  /* 32-bit far pointer to void */
#define T_32PFHRESULT       0x0508  /* 16:32 far pointer to HRESULT - or error code ??? */
#define T_32PFCHAR          0x0510  /* 16:32 far pointer to 8-bit signed */
#define T_32PFSHORT         0x0511  /* 16:32 far pointer to 16-bit signed */
#define T_32PFLONG          0x0512  /* 16:32 far pointer to 32-bit signed */
#define T_32PFQUAD          0x0513  /* 16:32 far pointer to 64-bit signed */
#define T_32PFUCHAR         0x0520  /* 16:32 far pointer to 8-bit unsigned */
#define T_32PFUSHORT        0x0521  /* 16:32 far pointer to 16-bit unsigned */
#define T_32PFULONG         0x0522  /* 16:32 far pointer to 32-bit unsigned */
#define T_32PFUQUAD         0x0523  /* 16:32 far pointer to 64-bit unsigned */
#define T_32PFBOOL08        0x0530  /* 16:32 far pointer to 8-bit Boolean */
#define T_32PFBOOL16        0x0531  /* 16:32 far pointer to 16-bit Boolean */
#define T_32PFBOOL32        0x0532  /* 16:32 far pointer to 32-bit Boolean */
#define T_32PFBOOL64        0x0533  /* 16:32 far pointer to 64-bit Boolean */
#define T_32PFREAL32        0x0540  /* 16:32 far pointer to 32-bit real */
#define T_32PFREAL64        0x0541  /* 16:32 far pointer to 64-bit real */
#define T_32PFREAL80        0x0542  /* 16:32 far pointer to 80-bit real */
#define T_32PFREAL128       0x0543  /* 16:32 far pointer to 128-bit real */
#define T_32PFREAL48        0x0544  /* 16:32 far pointer to 48-bit real */
#define T_32PFCPLX32        0x0550  /* 16:32 far pointer to 32-bit complex */
#define T_32PFCPLX64        0x0551  /* 16:32 far pointer to 64-bit complex */
#define T_32PFCPLX80        0x0552  /* 16:32 far pointer to 80-bit complex */
#define T_32PFCPLX128       0x0553  /* 16:32 far pointer to 128-bit complex */
#define T_32PFRCHAR         0x0570  /* 16:32 far pointer to a real char */
#define T_32PFWCHAR         0x0571  /* 16:32 far pointer to a wide char */
#define T_32PFINT2          0x0572  /* 16:32 far pointer to 16-bit signed int */
#define T_32PFUINT2         0x0573  /* 16:32 far pointer to 16-bit unsigned int */
#define T_32PFINT4          0x0574  /* 16:32 far pointer to 32-bit signed int */
#define T_32PFUINT4         0x0575  /* 16:32 far pointer to 32-bit unsigned int */
#define T_32PFINT8          0x0576  /* 16:32 far pointer to 64-bit signed int */
#define T_32PFUINT8         0x0577  /* 16:32 far pointer to 64-bit unsigned int */

/* 64-bit near pointers to basic types */
#define T_64PVOID           0x0603  /* 64-bit near pointer to void */
#define T_64PHRESULT        0x0608  /* 64 near pointer to HRESULT - or error code ??? */
#define T_64PCHAR           0x0610  /* 64 near pointer to 8-bit signed */
#define T_64PSHORT          0x0611  /* 64 near pointer to 16-bit signed */
#define T_64PLONG           0x0612  /* 64 near pointer to 32-bit signed */
#define T_64PQUAD           0x0613  /* 64 near pointer to 64-bit signed */
#define T_64PUCHAR          0x0620  /* 64 near pointer to 8-bit unsigned */
#define T_64PUSHORT         0x0621  /* 64 near pointer to 16-bit unsigned */
#define T_64PULONG          0x0622  /* 64 near pointer to 32-bit unsigned */
#define T_64PUQUAD          0x0623  /* 64 near pointer to 64-bit unsigned */
#define T_64PBOOL08         0x0630  /* 64 near pointer to 8-bit Boolean */
#define T_64PBOOL16         0x0631  /* 64 near pointer to 16-bit Boolean */
#define T_64PBOOL32         0x0632  /* 64 near pointer to 32-bit Boolean */
#define T_64PBOOL64         0x0633  /* 64 near pointer to 64-bit Boolean */
#define T_64PREAL32         0x0640  /* 64 near pointer to 32-bit real */
#define T_64PREAL64         0x0641  /* 64 near pointer to 64-bit real */
#define T_64PREAL80         0x0642  /* 64 near pointer to 80-bit real */
#define T_64PREAL128        0x0643  /* 64 near pointer to 128-bit real */
#define T_64PREAL48         0x0644  /* 64 near pointer to 48-bit real */
#define T_64PCPLX32         0x0650  /* 64 near pointer to 32-bit complex */
#define T_64PCPLX64         0x0651  /* 64 near pointer to 64-bit complex */
#define T_64PCPLX80         0x0652  /* 64 near pointer to 80-bit complex */
#define T_64PCPLX128        0x0653  /* 64 near pointer to 128-bit complex */
#define T_64PRCHAR          0x0670  /* 64 near pointer to a real char */
#define T_64PWCHAR          0x0671  /* 64 near pointer to a wide char */
#define T_64PINT2           0x0672  /* 64 near pointer to 16-bit signed int */
#define T_64PUINT2          0x0673  /* 64 near pointer to 16-bit unsigned int */
#define T_64PINT4           0x0674  /* 64 near pointer to 32-bit signed int */
#define T_64PUINT4          0x0675  /* 64 near pointer to 32-bit unsigned int */
#define T_64PINT8           0x0676  /* 64 near pointer to 64-bit signed int */
#define T_64PUINT8          0x0677  /* 64 near pointer to 64-bit unsigned int */

/* counts, bit masks, and shift values needed to access various parts of the built-in type numbers */
#define T_MAXPREDEFINEDTYPE 0x0580  /* maximum type index for all built-in types */
#define T_MAXBASICTYPE      0x0080  /* maximum type index all non-pointer built-in types */
#define T_BASICTYPE_MASK    0x00ff  /* mask of bits that can potentially identify a non-pointer basic type */
#define T_BASICTYPE_SHIFT   8       /* shift count to push out the basic type bits from a type number */
#define T_MODE_MASK         0x0700  /* type mode mask (ptr/non-ptr) */
#define T_SIZE_MASK         0x0007  /* type size mask (depends on 'type' value) */
#define T_TYPE_MASK         0x00f0  /* type type mask (data treatment mode) */

/* bit patterns for the <mode> portion of a built-in type number */
#define T_NEARPTR_BITS      0x0100
#define T_FARPTR_BITS       0x0200
#define T_HUGEPTR_BITS      0x0300
#define T_NEAR32PTR_BITS    0x0400
#define T_FAR32PTR_BITS     0x0500
#define T_NEAR64PTR_BITS    0x0600

#define LF_MODIFIER_V1          0x0001
#define LF_POINTER_V1           0x0002
#define LF_ARRAY_V1             0x0003
#define LF_CLASS_V1             0x0004
#define LF_STRUCTURE_V1         0x0005
#define LF_UNION_V1             0x0006
#define LF_ENUM_V1              0x0007
#define LF_PROCEDURE_V1         0x0008
#define LF_MFUNCTION_V1         0x0009
#define LF_VTSHAPE_V1           0x000a
#define LF_COBOL0_V1            0x000b
#define LF_COBOL1_V1            0x000c
#define LF_BARRAY_V1            0x000d
#define LF_LABEL_V1             0x000e
#define LF_NULL_V1              0x000f
#define LF_NOTTRAN_V1           0x0010
#define LF_DIMARRAY_V1          0x0011
#define LF_VFTPATH_V1           0x0012
#define LF_PRECOMP_V1           0x0013
#define LF_ENDPRECOMP_V1        0x0014
#define LF_OEM_V1               0x0015
#define LF_TYPESERVER_V1        0x0016

#define LF_MODIFIER_V2          0x1001     /* variants with new 32-bit type indices (V2) */
#define LF_POINTER_V2           0x1002
#define LF_ARRAY_V2             0x1003
#define LF_CLASS_V2             0x1004
#define LF_STRUCTURE_V2         0x1005
#define LF_UNION_V2             0x1006
#define LF_ENUM_V2              0x1007
#define LF_PROCEDURE_V2         0x1008
#define LF_MFUNCTION_V2         0x1009
#define LF_COBOL0_V2            0x100a
#define LF_BARRAY_V2            0x100b
#define LF_DIMARRAY_V2          0x100c
#define LF_VFTPATH_V2           0x100d
#define LF_PRECOMP_V2           0x100e
#define LF_OEM_V2               0x100f

#define LF_SKIP_V1              0x0200
#define LF_ARGLIST_V1           0x0201
#define LF_DEFARG_V1            0x0202
#define LF_LIST_V1              0x0203
#define LF_FIELDLIST_V1         0x0204
#define LF_DERIVED_V1           0x0205
#define LF_BITFIELD_V1          0x0206
#define LF_METHODLIST_V1        0x0207
#define LF_DIMCONU_V1           0x0208
#define LF_DIMCONLU_V1          0x0209
#define LF_DIMVARU_V1           0x020a
#define LF_DIMVARLU_V1          0x020b
#define LF_REFSYM_V1            0x020c

#define LF_SKIP_V2              0x1200    /* variants with new 32-bit type indices (V2) */
#define LF_ARGLIST_V2           0x1201
#define LF_DEFARG_V2            0x1202
#define LF_FIELDLIST_V2         0x1203
#define LF_DERIVED_V2           0x1204
#define LF_BITFIELD_V2          0x1205
#define LF_METHODLIST_V2        0x1206
#define LF_DIMCONU_V2           0x1207
#define LF_DIMCONLU_V2          0x1208
#define LF_DIMVARU_V2           0x1209
#define LF_DIMVARLU_V2          0x120a

/* Field lists */
#define LF_BCLASS_V1            0x0400
#define LF_VBCLASS_V1           0x0401
#define LF_IVBCLASS_V1          0x0402
#define LF_ENUMERATE_V1         0x0403
#define LF_FRIENDFCN_V1         0x0404
#define LF_INDEX_V1             0x0405
#define LF_MEMBER_V1            0x0406
#define LF_STMEMBER_V1          0x0407
#define LF_METHOD_V1            0x0408
#define LF_NESTTYPE_V1          0x0409
#define LF_VFUNCTAB_V1          0x040a
#define LF_FRIENDCLS_V1         0x040b
#define LF_ONEMETHOD_V1         0x040c
#define LF_VFUNCOFF_V1          0x040d
#define LF_NESTTYPEEX_V1        0x040e
#define LF_MEMBERMODIFY_V1      0x040f

#define LF_BCLASS_V2            0x1400    /* variants with new 32-bit type indices (V2) */
#define LF_VBCLASS_V2           0x1401
#define LF_IVBCLASS_V2          0x1402
#define LF_FRIENDFCN_V2         0x1403
#define LF_INDEX_V2             0x1404
#define LF_MEMBER_V2            0x1405
#define LF_STMEMBER_V2          0x1406
#define LF_METHOD_V2            0x1407
#define LF_NESTTYPE_V2          0x1408
#define LF_VFUNCTAB_V2          0x1409
#define LF_FRIENDCLS_V2         0x140a
#define LF_ONEMETHOD_V2         0x140b
#define LF_VFUNCOFF_V2          0x140c
#define LF_NESTTYPEEX_V2        0x140d
#define LF_MEMBERMODIFY_V2		0x140e
#define LF_MANAGED_V2			0x140f

#define LF_TYPESERVER_V3		0x1501       /* not referenced from symbol */
#define LF_ENUMERATE_V3         0x1502
#define LF_ARRAY_V3             0x1503
#define LF_CLASS_V3             0x1504
#define LF_STRUCTURE_V3         0x1505
#define LF_UNION_V3             0x1506
#define LF_ENUM_V3              0x1507
#define LF_DIMARRAY_V3			0x1508
#define LF_PRECOMP_V3			0x1509       /* not referenced from symbol */
#define LF_ALIAS_V3				0x150a       /* alias (typedef) type */
#define LF_DEFARG_V3			0x150b
#define LF_FRIENDFCN_V3			0x150c
#define LF_MEMBER_V3            0x150d
#define LF_STMEMBER_V3          0x150e
#define LF_METHOD_V3            0x150f
#define LF_NESTTYPE_V3          0x1510
#define LF_ONEMETHOD_V3         0x1511
#define LF_NESTTYPEEX_V3		0x1512
#define LF_MEMBERMODIFY_V3		0x1513
#define LF_MANAGED_V3			0x1514
#define LF_TYPESERVER2_V3		0x1515

#define LF_STRIDED_ARRAY_V3		0x1516    /* same as LF_ARRAY, but with stride between adjacent elements */
#define LF_HLSL_V3				0x1517
#define LF_MODIFIER_EX_V3		0x1518
#define LF_INTERFACE_V3			0x1519
#define LF_BINTERFACE_V3		0x151a
#define LF_VECTOR_V3			0x151b
#define LF_MATRIX_V3			0x151c

#define LF_VFTABLE_V3			0x151d      /* a virtual function table */
//#define LF_ENDOFLEAFRECORD		LF_VFTABLE

//#define LF_TYPE_LAST			0x151e      /* one greater than the last type record */
//#define LF_TYPE_MAX				(LF_TYPE_LAST - 1)



#define LF_FUNC_ID				0x1601    /* global func ID */
#define LF_MFUNC_ID				0x1602    /* member func ID */
#define LF_BUILDINFO			0x1603    /* build info: tool, version, command line, src/pdb file */
#define LF_SUBSTR_LIST			0x1604    /* similar to LF_ARGLIST, for list of sub strings */
#define LF_STRING_ID			0x1605    /* string ID */

#define LF_UDT_SRC_LINE			0x1606    /* source and line on where an UDT is defined
											only generated by compiler */

#define LF_UDT_MOD_SRC_LINE		0x1607    /* module, source and line on where an UDT is defined */

#define LF_NUMERIC              0x8000    /* numeric leaf types */
#define LF_CHAR                 0x8000
#define LF_SHORT                0x8001
#define LF_USHORT               0x8002
#define LF_LONG                 0x8003
#define LF_ULONG                0x8004
#define LF_REAL32               0x8005
#define LF_REAL64               0x8006
#define LF_REAL80               0x8007
#define LF_REAL128              0x8008
#define LF_QUADWORD             0x8009
#define LF_UQUADWORD            0x800a
#define LF_REAL48               0x800b
#define LF_COMPLEX32            0x800c
#define LF_COMPLEX64            0x800d
#define LF_COMPLEX80            0x800e
#define LF_COMPLEX128           0x800f
#define LF_VARSTRING            0x8010

#define CV_CALL_NEAR_C		0x00 /* near right to left push, caller pops stack */
#define CV_CALL_FAR_C		0x01 /* far right to left push, caller pops stack */
#define CV_CALL_NEAR_PASCAL	0x02 /* near left to right push, callee pops stack */
#define CV_CALL_FAR_PASCAL	0x03 /* far left to right push, callee pops stack */
#define CV_CALL_NEAR_FAST	0x04 /* near left to right push with regs, callee pops stack */
#define CV_CALL_FAR_FAST	0x05 /* far left to right push with regs, callee pops stack */
#define CV_CALL_SKIPPED		0x06 /* skipped (unused) call index */
#define CV_CALL_NEAR_STD	0x07 /* near standard call */
#define CV_CALL_FAR_STD		0x08 /* far standard call */
#define CV_CALL_NEAR_SYS	0x09 /* near sys call */
#define CV_CALL_FAR_SYS		0x0a /* far sys call */
#define CV_CALL_THISCALL	0x0b /* this call (this passed in register) */
#define CV_CALL_MIPSCALL	0x0c /* Mips call */
#define CV_CALL_GENERIC		0x0d /* Generic call sequence */
#define CV_CALL_ALPHACALL	0x0e /* Alpha call */
#define CV_CALL_PPCCALL		0x0f /* PPC call */
#define CV_CALL_SHCALL		0x10 /* Hitachi SuperH call */
#define CV_CALL_ARMCALL		0x11 /* ARM call */
#define CV_CALL_AM33CALL	0x12 /* AM33 call */
#define CV_CALL_TRICALL		0x13 /* TriCore Call */
#define CV_CALL_SH5CALL		0x14 /* Hitachi SuperH-5 call */
#define CV_CALL_M32RCALL	0x15 /* M32R Call */
#define CV_CALL_CLRCALL		0x16 /* clr call */
#define CV_CALL_INLINE		0x17 /* Marker for routines always inlined and thus lacking a convention */
#define CV_CALL_NEAR_VECTOR	0x18 /* near left to right push with regs, callee pops stack */
#define CV_CALL_RESERVED	0x19  /* first unused call enumeration */
// Do NOT add any more machine specific conventions.  This is to be used for
// calling conventions in the source only (e.g. __cdecl, __stdcall).

// enumeration for type modifier values
// 0x0000 - 0x01ff - Reserved.
#define CV_MOD_INVALID			0x0000
// Standard modifiers.
#define CV_MOD_CONST			0x0001
#define CV_MOD_VOLATILE			0x0002
#define CV_MOD_UNALIGNED		0x0003
// 0x0200 - 0x03ff - HLSL modifiers.
#define CV_MOD_HLSL_UNIFORM		0x0200
#define CV_MOD_HLSL_LINE		0x0201
#define CV_MOD_HLSL_TRIANGLE	0x0202
#define CV_MOD_HLSL_LINEADJ		0x0203
#define CV_MOD_HLSL_TRIANGLEADJ	0x0204
#define CV_MOD_HLSL_LINEAR		0x0205
#define CV_MOD_HLSL_CENTROID	0x0206
#define CV_MOD_HLSL_CONSTINTERP	0x0207
#define CV_MOD_HLSL_NOPERSPECTIVE	0x0208
#define CV_MOD_HLSL_SAMPLE		0x0209
#define CV_MOD_HLSL_CENTER		0x020a
#define CV_MOD_HLSL_SNORM		0x020b
#define CV_MOD_HLSL_UNORM		0x020c
#define CV_MOD_HLSL_PRECISE		0x020d
#define CV_MOD_HLSL_UAV_GLOBALLY_COHERENT 0x020e
// 0x0400 - 0xffff - Unused.

// enumeration for virtual shape table entries
#define CV_VTS_near         0x00
#define CV_VTS_far          0x01
#define CV_VTS_thin         0x02
#define CV_VTS_outer        0x03
#define CV_VTS_meta         0x04
#define CV_VTS_near32       0x05
#define CV_VTS_far32        0x06
#define CV_VTS_unused       0x07

// enumeration for LF_MODIFIER values
#define CV_modifier_const		1
#define CV_modifier_volatile	2
#define CV_modifier_unaligned	4

#define CV_MTvanilla        0x00
#define CV_MTvirtual        0x01
#define CV_MTstatic         0x02
#define CV_MTfriend         0x03
#define CV_MTintro          0x04
#define CV_MTpurevirt       0x05
#define CV_MTpureintro      0x06

#define CV_fldattr_noaccess    0x00
#define CV_fldattr_private     0x01
#define CV_fldattr_protected   0x02
#define CV_fldattr_public      0x03
#define CV_fldattr_MTvanilla   (CV_MTvanilla << 2)  
#define CV_fldattr_MTvirtual   (CV_MTvirtual << 2)  
#define CV_fldattr_MTstatic    (CV_MTstatic << 2)   
#define CV_fldattr_MTfriend    (CV_MTfriend << 2)   
#define CV_fldattr_MTintro     (CV_MTintro << 2)    
#define CV_fldattr_MTpurevirt  (CV_MTpurevirt << 2) 
#define CV_fldattr_MTpureintro (CV_MTpureintro << 2)
#define CV_fldattr_MTreserved  (0x07 << 2)
#define CV_fldattr_MTmask	   CV_fldattr_MTreserved
#define CV_fldattr_pseudo      0x20    /* compiler generated fcn and does not exist */
#define CV_fldattr_noinherit   0x40    /* true if class cannot be inherited */
#define CV_fldattr_noconstruct 0x80    /* true if class cannot be constructed */
#define CV_fldattr_compgenx    0x100   /* compiler generated fcn and does exist */
#define CV_fldattr_sealed      0x200   /* true if method cannot be overridden */

#define CV_funcattr_cxxreturnudt	1  /* true if C++ style ReturnUDT */
#define CV_funcattr_ctor			2  /* true if func is an instance constructor */
#define CV_funcattr_ctorvbase		4  /* true if func is an instance constructor of a class with virtual bases */

#define CV_PTR_BASE_MASK	0x1f
#define CV_PTR_NEAR			0x00 /* 16 bit pointer */
#define CV_PTR_FAR			0x01 /* 16:16 far pointer */
#define CV_PTR_HUGE			0x02 /* 16:16 huge pointer */
#define CV_PTR_BASE_SEG		0x03 /* based on segment */
#define CV_PTR_BASE_VAL		0x04 /* based on value of base */
#define CV_PTR_BASE_SEGVAL	0x05 /* based on segment value of base */
#define CV_PTR_BASE_ADDR	0x06 /* based on address of base */
#define CV_PTR_BASE_SEGADDR	0x07 /* based on segment address of base */
#define CV_PTR_BASE_TYPE	0x08 /* based on type */
#define CV_PTR_BASE_SELF	0x09 /* based on self */
#define CV_PTR_NEAR32		0x0a /* 32 bit pointer */
#define CV_PTR_FAR32		0x0b /* 16:32 pointer */
#define CV_PTR_64			0x0c /* 64 bit pointer */
#define CV_PTR_UNUSEDPTR	0x0d /* first unused pointer type */

#define CV_PTR_MODE_MASK	(0x07 << 5)
#define CV_PTR_MODE_PTR		(0x00 << 5) /* "normal" pointer */
#define CV_PTR_MODE_REF		(0x01 << 5) /* "old" reference */
#define CV_PTR_MODE_LVREF	(0x01 << 5) /* l-value reference */
#define CV_PTR_MODE_PMEM	(0x02 << 5) /* pointer to data member */
#define CV_PTR_MODE_PMFUNC	(0x03 << 5) /* pointer to member function */
#define CV_PTR_MODE_RVREF	(0x04 << 5) /* r-value reference */
#define CV_PTR_MODE_RESERVED	(0x05 << 5)  /* first unused pointer mode */

#define CV_PTR_isflat32		(1 << 8) /* true if 0:32 pointer */
#define CV_PTR_isvolatile	(1 << 9) /* TRUE if volatile pointer */
#define CV_PTR_isconst		(1 << 10) /* TRUE if const pointer */
#define CV_PTR_isunaligned	(1 << 11) /* TRUE if unaligned pointer */
#define CV_PTR_isrestrict	(1 << 12) /* TRUE if restricted pointer (allow agressive opts) */
#define CV_PTR_size_mask	(0x3f << 13)
#define CV_PTR_size(s)		(((s)&0x3f) << 13) /* size of pointer (in bytes) */
#define CV_PTR_ismocom		(1 << 19) /* TRUE if it is a MoCOM pointer (^ or %) */
#define CV_PTR_islref		(1 << 20) /* TRUE if it is this pointer of member function with & ref-qualifier */
#define CV_PTR_isrref		(1 << 21) /* TRUE if it is this pointer of member function with && ref-qualifier */

#define CV_PMTYPE_Undef			0x00 /* not specified (pre VC8) */
#define CV_PMTYPE_D_Single		0x01 /* member data, single inheritance */
#define CV_PMTYPE_D_Multiple	0x02 /* member data, multiple inheritance */
#define CV_PMTYPE_D_Virtual		0x03 /* member data, virtual inheritance */
#define CV_PMTYPE_D_General		0x04 /* member data, most general */
#define CV_PMTYPE_F_Single		0x05 /* member function, single inheritance */
#define CV_PMTYPE_F_Multiple	0x06 /* member function, multiple inheritance */
#define CV_PMTYPE_F_Virtual		0x07 /* member function, virtual inheritance */
#define CV_PMTYPE_F_General		0x08 /* member function, most general */


/* ======================================== *
 *            Symbol information
 * ======================================== */

// represents an address range, used for optimized code debug info

struct CV_LVAR_ADDR_RANGE {       // defines a range of addresses
	unsigned long   offStart;
	unsigned short  isectStart;
	unsigned short  cbRange;
};

// Represents the holes in overall address range, all address is pre-bbt. 
// it is for compress and reduce the amount of relocations need.

struct CV_LVAR_ADDR_GAP {
	unsigned short  gapStartOffset;   // relative offset from the beginning of the live range.
	unsigned short  cbRange;          // length of this gap.
};

union codeview_symbol
{
    struct
    {
        short int	        len;
        short int	        id;
    } generic;

	struct
	{
		short int	        len;
		short int	        id;
		unsigned long		pparent;    // pointer to the parent
		unsigned long		pend;       // pointer to this blocks end
	} generic_block;

	struct
	{
		short int	        len;
		short int	        id;
		unsigned long		pparent;    // pointer to the parent
		unsigned long		pend;       // pointer to this blocks end
	} generic_with;

	struct
	{
		short int	        len;
		short int	        id;
		unsigned long		pparent;    // pointer to the parent
		unsigned long		pend;       // pointer to this blocks end
		unsigned long		pnext;      // pointer to next symbol
	} generic_proc;

	struct
	{
		short int	        len;
		short int	        id;
		unsigned long		pparent;    // pointer to the parent
		unsigned long		pend;       // pointer to this blocks end
		unsigned long		pnext;      // pointer to next symbol
	} generic_thunk;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        symtype;
        struct p_string         p_name;
    } data_v1;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        symtype;
	unsigned int	        offset;
	unsigned short	        segment;
        struct p_string         p_name;
    } data_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];
    } data_v3;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        thunk_len;
	unsigned char	        thtype;
        struct p_string         p_name;
    } thunk_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            offset;
        unsigned short          segment;
        unsigned short          thunk_len;
        unsigned char           thtype;
        char                    name[1];
    } thunk_v3;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        proctype;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v1;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	unsigned int	        proctype;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            proc_len;
        unsigned int            debug_start;
        unsigned int            debug_end;
        unsigned int            proctype;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        char                    name[1];
    } proc_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } public_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];
    } public_v3;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_BPREL_V1 */
	unsigned int	        offset;	        /* Stack offset relative to BP */
	unsigned short	        symtype;
        struct p_string         p_name;
    } stack_v1;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_BPREL_V2 */
	unsigned int	        offset;	        /* Stack offset relative to EBP */
	unsigned int	        symtype;
        struct p_string         p_name;
    } stack_v2;

    struct
    {
        short int               len;            /* Total length of this entry */
        short int               id;             /* Always S_BPREL_V3 */
        int                     offset;         /* Stack offset relative to BP */
        unsigned int            symtype;
        char                    name[1];
    } stack_v3;

    struct
    {
        short int               len;            /* Total length of this entry */
        short int               id;             /* Always S_BPREL_V3 */
        int                     offset;         /* Stack offset relative to BP */
        unsigned int            symtype;
        unsigned short          reg;
        char                    name[1];
    } regrel_v3;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER */
        unsigned short          type;
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v1;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER_V2 */
        unsigned int            type;           /* check whether type & reg are correct */
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v2;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER_V3 */
        unsigned int            type;           /* check whether type & reg are correct */
        unsigned short          reg;
        char                    name[1];
        /* don't handle register tracking */
    } register_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } block_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];
    } block_v3;

	struct
	{
		short int			len;		// Record length
		short int			id;			// S_INLINESITE
		unsigned long		pParent;	// pointer to the inliner
		unsigned long		pEnd;		// pointer to this block's end
		unsigned long       inlinee;	// CV_ItemId of inlinee
#if 0
		unsigned char		binaryAnnotations[0];   // an array of compressed binary annotations.
#endif
	} inline_site;

	struct
	{
		short int			len;			// Record length
		short int			id;				// S_INLINESITE2
		unsigned long		pParent;        // pointer to the inliner
		unsigned long		pEnd;           // pointer to this block's end
		unsigned long       inlinee;        // CV_ItemId of inlinee
		unsigned long		invocations;    // entry count
#if 0
		unsigned char		binaryAnnotations[0];   // an array of compressed binary annotations.
#endif
	} inline_site2;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_LOCAL_V2 */
		unsigned int		type;           /* check whether type & reg are correct */
		unsigned short		flags;	// local var flags
		struct p_string     p_name;   // Name of this symbol, a null terminated array of UTF8 characters.
	} local_v2;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_LOCAL_V3 */
		unsigned int		type;           /* check whether type & reg are correct */
		unsigned short		flags;	// local var flags
		unsigned char		name[1];   // Name of this symbol, a null terminated array of UTF8 characters.
	} local_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_V3 */

		unsigned long   program;    // DIA program to evaluate the value of the symbol

		CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0]; // The value is not available in following gaps. 
#endif
	} range_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_SUBFIELD */

		unsigned long   program;    // DIA program to evaluate the value of the symbol

		unsigned long   offParent;  // Offset in parent variable.

		CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0];  // The value is not available in following gaps. 
#endif
	} range_subfield_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_REGISTER */
		unsigned short     reg;        // Register to hold the value of the symbol
		unsigned short     attr;       // Attribute of the register range.
		//{
		//	unsigned short  maybe : 1;    // May have no user name on one of control flow path.
		//}
		CV_LVAR_ADDR_RANGE range;      // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0];  // The value is not available in following gaps. 
#endif
	} range_register_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_FRAMEPOINTER_REL */

		unsigned long    offFramePointer;  // offset to frame pointer

		CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0];  // The value is not available in following gaps. 
#endif
	} range_stack_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE */

		unsigned long    offFramePointer;  // offset to frame pointer
	} range_stack_fullscope_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_REGISTER_REL */

		unsigned short  baseReg;         // Register to hold the base pointer of the symbol
		//unsigned short  spilledUdtMember : 1;   // Spilled member for s.i.
		//unsigned short  padding : 3;   // Padding for future use.
		unsigned short  offsetParent /*: 12*/;  // Offset in parent variable. (shift left 4 bits)
		unsigned long   offBasePointer;  // offset to register

		CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0];  // The value is not available in following gaps.
#endif
	} range_regrel_v3;

	struct
	{
		short int	        len;	        /* Total length of this entry */
		short int	        id;		/* Always S_DEFRANGE_SUBFIELD_REGISTER */

		unsigned short     reg;        // Register to hold the value of the symbol
		unsigned short     attr;       // Attribute of the register range.
		//{
		//	unsigned short  maybe : 1;    // May have no user name on one of control flow path.
		//}
		unsigned long      offParent /*: 12*/;  // Offset in parent variable.
		//unsigned long      padding : 20;  // Padding for future use.
		CV_LVAR_ADDR_RANGE range;   // Range of addresses where this program is valid
#if 0
		CV_LVAR_ADDR_GAP   gaps[0];  // The value is not available in following gaps. 
#endif
	} range_subfield_reg_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags; //CV_PFLAG_*
        struct p_string         p_name;
    } label_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags; //CV_PFLAG_*
        char                    name[1];
    } label_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned short          type;
        unsigned short          cvalue;         /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } constant_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        unsigned short          cvalue;         /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } constant_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        unsigned short          cvalue;
#if 0
        char                    name[1];
#endif
    } constant_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned short          type;
        struct p_string         p_name;
    } udt_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        struct p_string         p_name;
    } udt_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            type;
        char                    name[1];
    } udt_v3;

    struct
    {
        short int               len;
        short int               id;
		unsigned int            signature;
		struct p_string         p_name;
    } objname_v1;

	struct
	{
		short int               len;
		short int               id;
		unsigned int            signature;
		char                    name[1];
	} objname_v3;

    struct
    {
        short int               len;
        short int               id;
		unsigned char			machine;	// target processor
		unsigned char			language;	// language index
		unsigned short			flags;
		struct p_string         p_version;	// Length-prefixed compiler version string
	} compiland_v1;

	struct
	{
		short int               len;
		short int               id;
		unsigned int			flags;
		unsigned short			machine;    // target processor
		unsigned short			verFEMajor; // front end major version #
		unsigned short			verFEMinor; // front end minor version #
		unsigned short			verFEBuild; // front end build version #
		unsigned short			verMajor;   // back end major version #
		unsigned short			verMinor;   // back end minor version #
		unsigned short			verBuild;   // back end build version #
		struct p_string			p_version;  // Length-prefixed compiler version string, followed
											//  by an optional block of zero terminated strings
											//  terminated with a double zero.
	} compiland2_v2;

	struct
	{
		short int               len;
		short int               id;
		unsigned int			flags;
		unsigned short			machine;    // target processor
		unsigned short			verFEMajor; // front end major version #
		unsigned short			verFEMinor; // front end minor version #
		unsigned short			verFEBuild; // front end build version #
		unsigned short			verMajor;   // back end major version #
		unsigned short			verMinor;   // back end minor version #
		unsigned short			verBuild;   // back end build version #
		char					version[1]; // Zero terminated compiler version string, followed
											//  by an optional block of zero terminated strings
											//  terminated with a double zero.
	} compiland2_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned short          symtype;
        struct p_string         p_name;
    } thread_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } thread_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];
    } thread_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
    } ssearch_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;			// Frame relative offset
        unsigned short          reg;			// Register index
		unsigned char			cookietype;		// Type of the cookie
		unsigned char			flags;			// Flags describing this cookie
	} security_cookie_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            cb_frame;       /* count of bytes of total frame */
        unsigned int            cb_pad;			/* count of bytes of padding in the frame */
        unsigned int            offpad;			/* offset (relative to frame pointer) padding*/
        unsigned int            cb_saved_regs;  /* count of bytes of saved registers from callee */
        unsigned int            eh_offset;      /* offset for exception handler */
        unsigned short          eh_sect;        /* section for exception handler */
        unsigned int            flags;			/* CV_FIFLAG */
		// hasAlloca,hasSetjmp,hasLongjmp,hasInlAsm,hasEH,inl_specified,hasSEH,naked,hasGsChecks,hasEHa,noStackOrdering,wasInlined,strictGsCheck
		// return UDT,instance constructor,instance constructor with virtual base
	} frame_info_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            checksum;
        unsigned int            offset;
        unsigned int            module;
        struct p_string         p_name;  // not included in len
    } procref_v1;

	struct
	{
		short int               len;
		short int               id;
		unsigned int			flags;
		unsigned short			machine;    // target processor
		unsigned short			verFEMajor; // front end major version #
		unsigned short			verFEMinor; // front end minor version #
		unsigned short			verFEBuild; // front end build version #
		unsigned short			verFEQFE;   // front end QFE version #
		unsigned short			verMajor;   // back end major version #
		unsigned short			verMinor;   // back end minor version #
		unsigned short			verBuild;   // back end build version #
		unsigned short			verQFE;     // back end QFE version #
		char					version[1]; // Zero terminated compiler version string
	} ms_compiland3_v3;

	struct
	{
		short int               len;
		short int               id;
		unsigned char           flags;
		unsigned char			rgsz[1];    // Sequence of zero-terminated strings
	} ms_toolenv_v3;
};

#define S_COMPILAND_V1  0x0001
#define S_REGISTER_V1   0x0002
#define S_CONSTANT_V1   0x0003
#define S_UDT_V1        0x0004
#define S_SSEARCH_V1    0x0005
#define S_END_V1        0x0006
#define S_SKIP_V1       0x0007
#define S_CVRESERVE_V1  0x0008
#define S_OBJNAME_V1    0x0009
#define S_ENDARG_V1     0x000a
#define S_COBOLUDT_V1   0x000b
#define S_MANYREG_V1    0x000c
#define S_RETURN_V1     0x000d
#define S_ENTRYTHIS_V1  0x000e

#define S_BPREL_V1      0x0200
#define S_LDATA_V1      0x0201
#define S_GDATA_V1      0x0202
#define S_PUB_V1        0x0203
#define S_LPROC_V1      0x0204
#define S_GPROC_V1      0x0205
#define S_THUNK_V1      0x0206
#define S_BLOCK_V1      0x0207
#define S_WITH_V1       0x0208
#define S_LABEL_V1      0x0209
#define S_CEXMODEL_V1   0x020a
#define S_VFTPATH_V1    0x020b
#define S_REGREL_V1     0x020c
#define S_LTHREAD_V1    0x020d
#define S_GTHREAD_V1    0x020e

#define S_PROCREF_V1    0x0400
#define S_DATAREF_V1    0x0401
#define S_ALIGN_V1      0x0402
#define S_LPROCREF_V1   0x0403

#define S_REGISTER_V2   0x1001 /* Variants with new 32-bit type indices */
#define S_CONSTANT_V2   0x1002
#define S_UDT_V2        0x1003
#define S_COBOLUDT_V2   0x1004
#define S_MANYREG_V2    0x1005
#define S_BPREL_V2      0x1006
#define S_LDATA_V2      0x1007
#define S_GDATA_V2      0x1008
#define S_PUB_V2        0x1009
#define S_LPROC_V2      0x100a
#define S_GPROC_V2      0x100b
#define S_VFTTABLE_V2   0x100c
#define S_REGREL_V2     0x100d
#define S_LTHREAD_V2    0x100e
#define S_GTHREAD_V2    0x100f
#define S_FRAMEINFO_V2  0x1012
#define S_COMPILAND2_V2 0x1013

#define S_OBJNAME_V3	0x1101
#define S_THUNK_V3      0x1102
#define S_BLOCK_V3      0x1103
#define S_LABEL_V3      0x1105
#define S_REGISTER_V3   0x1106
#define S_CONSTANT_V3   0x1107
#define S_UDT_V3        0x1108
#define S_BPREL_V3      0x110B
#define S_LDATA_V3      0x110C
#define S_GDATA_V3      0x110D
#define S_PUB_V3        0x110E
#define S_LPROC_V3      0x110F
#define S_GPROC_V3      0x1110
#define S_REGREL_V3     0x1111
#define S_LTHREAD_V3    0x1112
#define S_GTHREAD_V3    0x1113
#define S_COMPILAND2_V3 0x1116  /* compiler command line options and build information */
#define S_PUB_FUNC1_V3  0x1125  /* didn't get the difference between the two */
#define S_PUB_FUNC2_V3  0x1127
#define S_LOCAL_V2		0x1133  /* defines a local symbol in optimized code */
#define S_DEFRANGE_V2	0x1134  /* defines a single range of addresses in which symbol can be evaluated */
#define S_DEFRANGE2_V2	0x1135 /* defines ranges of addresses in which symbol can be evaluated */
#define S_SECTINFO_V3   0x1136
#define S_SUBSECTINFO_V3 0x1137
#define S_ENTRYPOINT_V3 0x1138
#define S_SECUCOOKIE_V3 0x113A
#define S_COMPILAND3_V3	0x113C	/* compiler command line options and build information */
#define S_MSTOOLENV_V3  0x113D	/* environment block split of S_COMPILAND2_V3 */
#define S_LOCAL_V3		0x113e	/* defines a local symbol in optimized code */
#define S_DEFRANGE_V3	0x113f	/* defines a single range of addresses in which symbol can be evaluated */
#define S_DEFRANGE_SUBFIELD_V3	0x1140       /* ranges for a subfield */

#define S_DEFRANGE_REGISTER_V3	0x1141       /* ranges for en-registered symbol */
#define S_DEFRANGE_FRAMEPOINTER_REL_V3	0x1142   /* range for stack symbol. */
#define S_DEFRANGE_SUBFIELD_REGISTER_V3 0x1143  /* ranges for en-registered field of symbol */
#define S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE_V3 0x1144 /* range for stack symbol span valid full scope of function body, gap might apply. */
#define S_DEFRANGE_REGISTER_REL_V3 0x1145 /* range for symbol address as register + offset. */

// S_PROC symbols that reference ID instead of type
#define S_LPROC32_ID	0x1146
#define S_GPROC32_ID	0x1147
#define S_LPROCMIPS_ID	0x1148
#define S_GPROCMIPS_ID	0x1149
#define S_LPROCIA64_ID	0x114a
#define S_GPROCIA64_ID	0x114b

#define S_BUILDINFO		0x114c /* build information. */
#define S_INLINESITE	0x114d /* inlined function callsite. */
#define S_INLINESITE_END	0x114e
#define S_PROC_ID_END	0x114f

/* procedure symbol flags */
#define CV_PFLAG_NOFPO		0x01 /* frame pointer present */
#define CV_PFLAG_INT		0x02 /* interrupt return */
#define CV_PFLAG_FAR		0x04 /* far return */
#define CV_PFLAG_NEVER		0x08 /* function does not return */
#define CV_PFLAG_NOTREACHED	0x10 /* label isn't fallen into */
#define CV_PFLAG_CUST_CALL	0x20 /* custom calling convention */
#define CV_PFLAG_NOINLINE	0x40 /* function marked as noinline */
#define CV_PFLAG_OPTDBGINFO	0x80 /* function has debug information for optimized code */

/* frame info flags and masks */
#define CV_FIFLAG_HasAlloca		0x000001   /* function uses _alloca() */
#define CV_FIFLAG_HasSetJmp		0x000002   /* function uses setjmp() */
#define CV_FIFLAG_HasLongJmp	0x000004   /* function uses longjmp() */
#define CV_FIFLAG_HasInlAsm		0x000008   /* function uses inline asm */
#define CV_FIFLAG_HasEH			0x000010   /* function has EH states */
#define CV_FIFLAG_InlSpec		0x000020   /* function was speced as inline */
#define CV_FIFLAG_HasSEH		0x000040   /* function has SEH */
#define CV_FIFLAG_Naked			0x000080   /* function is __declspec(naked) */
#define CV_FIFLAG_SecurityChecks   0x000100  /* function has buffer security check introduced by /GS. */
#define CV_FIFLAG_AsyncEH		0x000200   /* function compiled with /EHa */
#define CV_FIFLAG_GSNoStackOrdering   0x000400   // function has /GS buffer checks, but stack ordering couldn't be done */
#define CV_FIFLAG_WasInlined	0x000800   /* function was inlined within another function */
#define CV_FIFLAG_GSCheck		0x001000   /* function is __declspec(strict_gs_check) */
#define CV_FIFLAG_SafeBuffers	0x002000   /* function is __declspec(safebuffers) */
#define CV_FIMASK_encodedLocalBasePointer  0x00C000  /* record function's local pointer explicitly. */
#define CV_FIMASK_encodedParamBasePointer  0x030000  /* record function's parameter pointer explicitly. */
#define CV_FIVALUE_encodedLocalBasePointer(reg) (((reg)&3) << 14)
#define CV_FIVALUE_encodedParamBasePointer(reg) (((reg)&3) << 16)
#define CV_FIFLAG_PogoOn		0x040000   /* function was compiled with PGO/PGU */
#define CV_FIFLAG_ValidCounts	0x080000   /* Do we have valid Pogo counts? */
#define CV_FIFLAG_OptSpeed		0x100000   /* Did we optimize for speed? */
#define CV_FIFLAG_GuardCF		0x200000   /* function contains CFG checks (and no write checks) */
#define CV_FIFLAG_GuardCFW		0x400000   /* function contains CFW checks and/or instrumentation */

#define CV_LVARFLAGS_fIsParam			0x001 /* variable is a parameter */
#define CV_LVARFLAGS_fAddrTaken			0x002 /* address is taken */
#define CV_LVARFLAGS_fCompGenx			0x004 /* variable is compiler generated */
#define CV_LVARFLAGS_fIsAggregate		0x008 /* the symbol is splitted in temporaries,
												  which are treated by compiler as 
												  independent entities */
#define CV_LVARFLAGS_fIsAggregated		0x010 /* Counterpart of fIsAggregate - tells
												  that it is a part of a fIsAggregate symbol */
#define CV_LVARFLAGS_fIsAliased			0x020 /* variable has multiple simultaneous lifetimes */
#define CV_LVARFLAGS_fIsAlias			0x040 /* represents one of the multiple simultaneous lifetimes */
#define CV_LVARFLAGS_fIsRetValue		0x080 /* represents a function return value */
#define CV_LVARFLAGS_fIsOptimizedOut	0x100 /* variable has no lifetimes */
#define CV_LVARFLAGS_fIsEnregGlob		0x200 /* variable is an enregistered global */
#define CV_LVARFLAGS_fIsEnregStat		0x400 /* variable is an enregistered static */


// Frame cookie information
#define CV_COOKIETYPE_COPY		0
#define CV_COOKIETYPE_XOR_SP	1
#define CV_COOKIETYPE_XOR_BP	2
#define CV_COOKIETYPE_XOR_R13	3

/* compile flags and masks */
#define CV_CFL_PCODE		0x001
#define CV_CFL_FLOATPREC	0x006
#define CV_CFL_FLOATPKG		0x018
#define CV_CFL_AMBDATA		0x0E0
#define CV_CFL_AMBCODE		0x700
#define CV_CFL_MODE32		0x800

/* data models */
#define CV_CFL_DNEAR		0x00
#define CV_CFL_DFAR 		0x20
#define CV_CFL_DHUGE		0x40

/* code models */
#define CV_CFL_CNEAR		0x000
#define CV_CFL_CFAR 		0x100
#define CV_CFL_CHUGE		0x200

/* floating point packages */
#define CV_CFL_NDP			0x00
#define CV_CFL_EMU			0x08
#define CV_CFL_ALT			0x10

/* languages */
#define CV_CFL_C			0x00
#define CV_CFL_CXX			0x01
#define CV_CFL_FORTRAN		0x02
#define CV_CFL_MASM			0x03
#define CV_CFL_PASCAL		0x04
#define CV_CFL_BASIC		0x05
#define CV_CFL_COBOL		0x06
#define CV_CFL_LINK			0x07
#define CV_CFL_CVTRES		0x08
#define CV_CFL_CVTPGD		0x09
#define CV_CFL_CSHARP		0x0A  /* C# */
#define CV_CFL_VB			0x0B  /* Visual Basic */
#define CV_CFL_ILASM		0x0C  /* IL (as in CLR) ASM */
#define CV_CFL_JAVA			0x0D
#define CV_CFL_JSCRIPT		0x0E
#define CV_CFL_MSIL			0x0F  /* Unknown MSIL (LTCG of .NETMODULE) */
#define CV_CFL_HLSL			0x10  /* High Level Shader Language */

/* machines */
#define CV_CFL_8080         0x00
#define CV_CFL_8086         0x01
#define CV_CFL_80286        0x02
#define CV_CFL_80386        0x03
#define CV_CFL_80486        0x04
#define CV_CFL_PENTIUM      0x05
#define CV_CFL_PENTIUMII    0x06
#define CV_CFL_PENTIUMPRO   CV_CFL_PENTIUMII
#define CV_CFL_PENTIUMIII   0x07
#define CV_CFL_MIPS         0x10
#define CV_CFL_MIPSR4000    CV_CFL_MIPS  /* don't break current code */
#define CV_CFL_MIPS16       0x11
#define CV_CFL_MIPS32       0x12
#define CV_CFL_MIPS64       0x13
#define CV_CFL_MIPSI        0x14
#define CV_CFL_MIPSII       0x15
#define CV_CFL_MIPSIII      0x16
#define CV_CFL_MIPSIV       0x17
#define CV_CFL_MIPSV        0x18
#define CV_CFL_M68000       0x20
#define CV_CFL_M68010       0x21
#define CV_CFL_M68020       0x22
#define CV_CFL_M68030       0x23
#define CV_CFL_M68040       0x24
#define CV_CFL_ALPHA        0x30
#define CV_CFL_ALPHA_21064  0x30
#define CV_CFL_ALPHA_21164  0x31
#define CV_CFL_ALPHA_21164A 0x32
#define CV_CFL_ALPHA_21264  0x33
#define CV_CFL_ALPHA_21364  0x34
#define CV_CFL_PPC601       0x40
#define CV_CFL_PPC603       0x41
#define CV_CFL_PPC604       0x42
#define CV_CFL_PPC620       0x43
#define CV_CFL_PPCFP        0x44
#define CV_CFL_PPCBE        0x45
#define CV_CFL_SH3          0x50
#define CV_CFL_SH3E         0x51
#define CV_CFL_SH3DSP       0x52
#define CV_CFL_SH4          0x53
#define CV_CFL_SHMEDIA      0x54
#define CV_CFL_ARM3         0x60
#define CV_CFL_ARM4         0x61
#define CV_CFL_ARM4T        0x62
#define CV_CFL_ARM5         0x63
#define CV_CFL_ARM5T        0x64
#define CV_CFL_ARM6         0x65
#define CV_CFL_ARM_XMAC     0x66
#define CV_CFL_ARM_WMMX     0x67
#define CV_CFL_ARM7         0x68
#define CV_CFL_OMNI         0x70
#define CV_CFL_IA64         0x80
#define CV_CFL_IA64_1       0x80
#define CV_CFL_IA64_2       0x81
#define CV_CFL_CEE          0x90
#define CV_CFL_AM33         0xA0
#define CV_CFL_M32R         0xB0
#define CV_CFL_TRICORE      0xC0
#define CV_CFL_X64          0xD0
#define CV_CFL_AMD64        CV_CFL_X64
#define CV_CFL_EBC          0xE0
#define CV_CFL_THUMB        0xF0
#define CV_CFL_ARMNT        0xF4
#define CV_CFL_ARM64        0xF6
#define CV_CFL_D3D11_SHADER 0x100

#define CV_COMPILEMASK_LANGUAGE       0x000FF
#define CV_COMPILEFLAG_EC             0x00100
#define CV_COMPILEFLAG_NODBGINFO      0x00200
#define CV_COMPILEFLAG_LTCG           0x00400
#define CV_COMPILEFLAG_NODATAALIGN    0x00800
#define CV_COMPILEFLAG_MANAGEDPRESENT 0x01000
#define CV_COMPILEFLAG_SECURITYCHECKS 0x02000
#define CV_COMPILEFLAG_HOTPATCH       0x04000
#define CV_COMPILEFLAG_CVTCIL         0x08000
#define CV_COMPILEFLAG_MSILMODULE     0x10000
#define CV_COMPILEFLAG_SDL            0x20000
#define CV_COMPILEFLAG_PGO            0x40000
#define CV_COMPILEFLAG_EXP            0x80000

#define CV_PUBSYMFLAGS_cvpsfNone		0
#define CV_PUBSYMFLAGS_cvpsfCode		0x00000001
#define CV_PUBSYMFLAGS_cvpsfFunction	0x00000002
#define CV_PUBSYMFLAGS_cvpsfManaged		0x00000004
#define CV_PUBSYMFLAGS_cvpsfMSIL		0x00000008

#define CV_SEGDESCFLAGS_read			0x0001
#define CV_SEGDESCFLAGS_write			0x0002
#define CV_SEGDESCFLAGS_execute			0x0004
#define CV_SEGDESCFLAGS_reserved1		0x0008
#define CV_SEGDESCFLAGS_reserved2		0x0010
#define CV_SEGDESCFLAGS_reserved3		0x0020
#define CV_SEGDESCFLAGS_reserved4		0x0040
#define CV_SEGDESCFLAGS_reserved5		0x0080
#define CV_SEGDESCFLAGS_reserved6		0x0100
#define CV_SEGDESCFLAGS_reserved7		0x0200
#define CV_SEGDESCFLAGS_reserved8		0x0400
#define CV_SEGDESCFLAGS_reserved9		0x0800
#define CV_SEGDESCFLAGS_reserved10		0x1000
#define CV_SEGDESCFLAGS_reserved11		0x2000
#define CV_SEGDESCFLAGS_reserved12		0x4000
#define CV_SEGDESCFLAGS_reserved13		0x8000

#define THUNK_ORDINAL_NOTYPE		0	/* standard thunk */
#define THUNK_ORDINAL_ADJUSTOR		1	/* "this" adjustor thunk */
#define THUNK_ORDINAL_VCALL			2	/* virtual call thunk */
#define THUNK_ORDINAL_PCODE			3	/* pcode thunk */
#define THUNK_ORDINAL_LOAD			4	/* thunk which loads the address to jump to */
										//  via unknown means...

 // trampoline thunk ordinals   - only for use in Trampoline thunk symbols
 #define THUNK_ORDINAL_TRAMP_INCREMENTAL	5
 #define THUNK_ORDINAL_TRAMP_BRANCHISLAND	6


// BinaryAnnotations ::= BinaryAnnotationInstruction+
// BinaryAnnotationInstruction ::= BinaryAnnotationOpcode Operand+
//
// The binary annotation mechanism supports recording a list of annotations
// in an instruction stream.  The X64 unwind code and the DWARF standard have
// similar design.
//
// One annotation contains opcode and a number of 32bits operands.
//
// The initial set of annotation instructions are for line number table
// encoding only.  These annotations append to S_INLINESITE record, and
// operands are unsigned except for BA_OP_ChangeLineOffset.

enum BinaryAnnotationOpcode
{
	BA_OP_Invalid,               // link time pdb contains PADDINGs
	BA_OP_CodeOffset,            // param : start offset 
	BA_OP_ChangeCodeOffsetBase,  // param : nth separated code chunk (main code chunk == 0)
	BA_OP_ChangeCodeOffset,      // param : delta of offset
	BA_OP_ChangeCodeLength,      // param : length of code, default next start
	BA_OP_ChangeFile,            // param : fileId 
	BA_OP_ChangeLineOffset,      // param : line offset (signed)
	BA_OP_ChangeLineEndDelta,    // param : how many lines, default 1
	BA_OP_ChangeRangeKind,       // param : either 1 (default, for statement)
								 //         or 0 (for expression)

	BA_OP_ChangeColumnStart,     // param : start column number, 0 means no column info
	BA_OP_ChangeColumnEndDelta,  // param : end column number delta (signed)

	// Combo opcodes for smaller encoding size.

	BA_OP_ChangeCodeOffsetAndLineOffset,  // param : ((sourceDelta << 4) | CodeDelta)
	BA_OP_ChangeCodeLengthAndCodeOffset,  // param : codeLength, codeOffset

	BA_OP_ChangeColumnEnd,       // param : end column number
};

inline int BinaryAnnotationInstructionOperandCount(BinaryAnnotationOpcode op)
{
	return (op == BA_OP_ChangeCodeLengthAndCodeOffset) ? 2 : 1;
}

///////////////////////////////////////////////////////////////////////////////
//
// This routine a simplified variant from cor.h.
//
// Compress an unsigned integer (iLen) and store the result into pDataOut.
//
// Return value is the number of bytes that the compressed data occupies.  It
// is caller's responsibilityt to ensure *pDataOut has at least 4 bytes to be
// written to.
//
// Note that this function returns -1 if iLen is too big to be compressed.
// We currently can only encode numbers no larger than 0x1FFFFFFF.
//
///////////////////////////////////////////////////////////////////////////////

inline unsigned int CVCompressData(
	unsigned int  iLen,       // [IN]  given uncompressed data
	void *  pDataOut)   // [OUT] buffer for the compressed data
{
	byte *pBytes = reinterpret_cast<byte *>(pDataOut);

	if (iLen <= 0x7F) {
		*pBytes = byte(iLen);
		return 1;
	}

	if (iLen <= 0x3FFF) {
		*pBytes = byte((iLen >> 8) | 0x80);
		*(pBytes + 1) = byte(iLen & 0xff);
		return 2;
	}

	if (iLen <= 0x1FFFFFFF) {
		*pBytes = byte((iLen >> 24) | 0xC0);
		*(pBytes + 1) = byte((iLen >> 16) & 0xff);
		*(pBytes + 2) = byte((iLen >> 8) & 0xff);
		*(pBytes + 3) = byte(iLen & 0xff);
		return 4;
	}

	return (unsigned int)-1;
}

///////////////////////////////////////////////////////////////////////////////
//
// Uncompress the data in pData and store the result into pDataOut.
//
// Return value is the uncompressed unsigned integer.  pData is incremented to
// point to the next piece of uncompressed data.
// 
// Returns -1 if what is passed in is incorrectly compressed data, such as
// (*pBytes & 0xE0) == 0xE0.
//
///////////////////////////////////////////////////////////////////////////////

inline unsigned int CVUncompressData(
	byte* & pData)    // [IN,OUT] compressed data 
{
	unsigned int res = (unsigned int)(-1);

	if ((*pData & 0x80) == 0x00) {
		// 0??? ????

		res = (unsigned int)(*pData++);
	}
	else if ((*pData & 0xC0) == 0x80) {
		// 10?? ????

		res = (unsigned int)((*pData++ & 0x3f) << 8);
		res |= *pData++;
	}
	else if ((*pData & 0xE0) == 0xC0) {
		// 110? ???? 

		res = (*pData++ & 0x1f) << 24;
		res |= *pData++ << 16;
		res |= *pData++ << 8;
		res |= *pData++;
	}

	return res;
}

// Encode smaller absolute numbers with smaller buffer.
//
// General compression only work for input < 0x1FFFFFFF 
// algorithm will not work on 0x80000000 

inline unsigned __int32 EncodeSignedInt32(__int32 input)
{
	unsigned __int32 rotatedInput;

	if (input >= 0) {
		rotatedInput = input << 1;
	}
	else {
		rotatedInput = ((-input) << 1) | 1;
	}

	return rotatedInput;
}

inline __int32 DecodeSignedInt32(unsigned __int32 input)
{
	__int32 rotatedInput;

	if (input & 1) {
		rotatedInput = -(int)(input >> 1);
	}
	else {
		rotatedInput = input >> 1;
	}

	return rotatedInput;
}

/* ======================================== *
 *          Line number information
 * ======================================== */

struct codeview_linetab_block
{
    unsigned short              seg;
    unsigned short              num_lines;
    unsigned int                offsets[1];     /* in fact num_lines */
/*  unsigned short              linenos[]; */
};

struct startend
{
    unsigned int	        start;
    unsigned int	        end;
};

#define LT2_LINES_BLOCK 0x000000f2
#define LT2_FILES_BLOCK 0x000000f4

#define DEBUG_S_IGNORE	0x80000000    // if this bit is set in a subsection type then ignore the subsection contents

#define DEBUG_S_SYMBOLS				0x000000f1
#define DEBUG_S_LINES				0x000000f2
#define DEBUG_S_STRINGTABLE			0x000000f3
#define DEBUG_S_FILECHKSMS			0x000000f4
#define DEBUG_S_FRAMEDATA			0x000000f5
#define DEBUG_S_INLINEELINES		0x000000f6
#define DEBUG_S_CROSSSCOPEIMPORTS	0x000000f7
#define DEBUG_S_CROSSSCOPEEXPORTS	0x000000f8

#define DEBUG_S_IL_LINES			0x000000f9
#define DEBUG_S_FUNC_MDTOKEN_MAP	0x000000fa
#define DEBUG_S_TYPE_MDTOKEN_MAP	0x000000fb
#define DEBUG_S_MERGED_ASSEMBLYINPUT	0x000000fc

#define DEBUG_S_COFF_SYMBOL_RVA		0x000000fd

struct codeview_subsection_header
{
	DWORD type;
	long  cbLen;
};

/* there's a new line tab structure from MS Studio 2005 and after
 * it's made of a list of codeview_linetab2 blocks.
 * We've only seen (so far) list with a single LT2_FILES_BLOCK and several
 * LT2_LINES_BLOCK. The LT2_FILES block has been encountered either as first
 * or last block of the list.
 * A LT2_FILES contains one or several codeview_linetab2_file:s
 */

struct codeview_linetab2
{
    DWORD       header;
    DWORD       size_of_block;
};

static inline const struct codeview_linetab2* codeview_linetab2_next_block(const struct codeview_linetab2* lt2)
{
    return (const struct codeview_linetab2*)((const char*)(lt2 + 1) + lt2->size_of_block);
}

struct codeview_linetab2_file
{
    DWORD       offset;         /* offset in string table for filename */
    WORD        unk;            /* always 0x0110... type of following information ??? */
    BYTE        md5[16];        /* MD5 signature of file (signature on file's content or name ???) */
    WORD        pad0;           /* always 0 */
};

struct codeview_lt2blk_files
{
    struct codeview_linetab2            lt2;    /* LT2_FILES */
    struct codeview_linetab2_file       file[1];
};

struct codeview_lt2blk_lines
{
    struct codeview_linetab2    lt2;            /* LT2_LINE_BLOCK */
    DWORD                       start;          /* start address of function with line numbers */
    DWORD                       seg;            /* segment of function with line numbers */
    DWORD                       size;           /* size of function with line numbers */
    DWORD                       file_offset;    /* offset for accessing corresponding codeview_linetab2_file */
    DWORD                       nlines;         /* number of lines in this block */
    DWORD                       size_lines;     /* number of bytes following for line number information */
    struct {
        DWORD   offset;         /* offset (from <seg>:<start>) for line number */
        DWORD   lineno;         /* the line number (OR:ed with 0x80000000 why ???) */
    } l[1];                     /* actually array of <nlines> */
};

/* ======================================== *
 *            PDB file information
 * ======================================== */


struct PDB_FILE
{
    DWORD               size;
    DWORD               unknown;
};

struct PDB_JG_HEADER
{
    CHAR                ident[40];
    DWORD               signature;
    DWORD               block_size;
    WORD                free_list;
    WORD                total_alloc;
    struct PDB_FILE     toc;
    WORD                toc_block[1];
};

struct PDB_DS_HEADER
{
    char                signature[32];
    DWORD               block_size;
    DWORD               unknown1;
    DWORD               num_pages;
    DWORD               toc_size;
    DWORD               unknown2;
    DWORD               toc_page;
};

struct PDB_JG_TOC
{
    DWORD               num_files;
    struct PDB_FILE     file[1];
};

struct PDB_DS_TOC
{
    DWORD               num_files;
    DWORD               file_size[1];
};

struct PDB_JG_ROOT
{
    DWORD               Version;
    DWORD               TimeDateStamp;
    DWORD               Age;
    DWORD               cbNames;
    CHAR                names[1];
};

struct PDB_DS_ROOT
{
    DWORD               Version;
    DWORD               TimeDateStamp;
    DWORD               Age;
    GUID                guid;
    DWORD               cbNames;
    CHAR                names[1];
};

typedef struct _PDB_TYPES_OLD
{
    DWORD       version;
    WORD        first_index;
    WORD        last_index;
    DWORD       type_size;
    WORD        file;
    WORD        pad;
} PDB_TYPES_OLD, *PPDB_TYPES_OLD;

typedef struct _PDB_TYPES
{
    DWORD       version;
    DWORD       type_offset;
    DWORD       first_index;
    DWORD       last_index;
    DWORD       type_size;
    WORD        file;
    WORD        pad;
    DWORD       hash_size;
    DWORD       hash_base;
    DWORD       hash_offset;
    DWORD       hash_len;
    DWORD       search_offset;
    DWORD       search_len;
    DWORD       unknown_offset;
    DWORD       unknown_len;
} PDB_TYPES, *PPDB_TYPES;

typedef struct _PDB_SYMBOL_RANGE
{
    WORD        segment;
    WORD        pad1;
    DWORD       offset;
    DWORD       size;
    DWORD       characteristics;
    WORD        index;
    WORD        pad2;
} PDB_SYMBOL_RANGE, *PPDB_SYMBOL_RANGE;

typedef struct _PDB_SYMBOL_RANGE_EX
{
    WORD        segment;
    WORD        pad1;
    DWORD       offset;
    DWORD       size;
    DWORD       characteristics;
    WORD        index;
    WORD        pad2;
    DWORD       timestamp;
    DWORD       unknown;
} PDB_SYMBOL_RANGE_EX, *PPDB_SYMBOL_RANGE_EX;

typedef struct _PDB_SYMBOL_FILE
{
    DWORD       unknown1;
    PDB_SYMBOL_RANGE range;
    WORD        flag;
    WORD        file;
    DWORD       symbol_size;
    DWORD       lineno_size;
    DWORD       unknown2;
    DWORD       nSrcFiles;
    DWORD       attribute;
    CHAR        filename[1];
} PDB_SYMBOL_FILE, *PPDB_SYMBOL_FILE;

typedef struct _PDB_SYMBOL_FILE_EX
{
    DWORD       unknown1;
    PDB_SYMBOL_RANGE_EX range;
    WORD        flag;
    WORD        file;
    DWORD       symbol_size;
    DWORD       lineno_size;
    DWORD       unknown2;
    DWORD       nSrcFiles;
    DWORD       attribute;
    DWORD       reserved[2];
    CHAR        filename[1];
} PDB_SYMBOL_FILE_EX, *PPDB_SYMBOL_FILE_EX;

typedef struct _PDB_SYMBOL_SOURCE
{
    WORD        nModules;
    WORD        nSrcFiles;
    WORD        table[1];
} PDB_SYMBOL_SOURCE, *PPDB_SYMBOL_SOURCE;

typedef struct _PDB_SYMBOL_IMPORT
{
    DWORD       unknown1;
    DWORD       unknown2;
    DWORD       TimeDateStamp;
    DWORD       Age;
    CHAR        filename[1];
} PDB_SYMBOL_IMPORT, *PPDB_SYMBOL_IMPORT;

typedef struct _PDB_SYMBOLS_OLD
{
    WORD        hash1_file;
    WORD        hash2_file;
    WORD        gsym_file;
    WORD        pad;
    DWORD       module_size;
    DWORD       offset_size;
    DWORD       hash_size;
    DWORD       srcmodule_size;
} PDB_SYMBOLS_OLD, *PPDB_SYMBOLS_OLD;

typedef struct _PDB_SYMBOLS
{
    DWORD       signature;
    DWORD       version;
    DWORD       unknown;
    DWORD       hash1_file;
    DWORD       hash2_file;
    WORD        gsym_file;
    WORD        unknown1;
    DWORD       module_size;
    DWORD       offset_size;
    DWORD       hash_size;
    DWORD       srcmodule_size;
    DWORD       pdbimport_size;
    DWORD       resvd0;
    DWORD       stream_index_size;
    DWORD       unknown2_size;
    WORD        resvd3;
    WORD        machine;
    DWORD       resvd4;
} PDB_SYMBOLS, *PPDB_SYMBOLS;

typedef struct
{
    WORD        FPO;
    WORD        unk0;
    WORD        unk1;
    WORD        unk2;
    WORD        unk3;
    WORD        segments;
} PDB_STREAM_INDEXES_OLD;

typedef struct
{
    WORD        FPO;
    WORD        unk0;
    WORD        unk1;
    WORD        unk2;
    WORD        unk3;
    WORD        segments;
    WORD        unk4;
    WORD        unk5;
    WORD        unk6;
    WORD        FPO_EXT;
    WORD        unk7;
} PDB_STREAM_INDEXES;

typedef struct _PDB_FPO_DATA
{
    DWORD       start;
    DWORD       func_size;
    DWORD       locals_size;
    DWORD       params_size;
    DWORD       maxstack_size;
    DWORD       str_offset;
    WORD        prolog_size;
    WORD        savedregs_size;
#define PDB_FPO_DFL_SEH         0x00000001
#define PDB_FPO_DFL_EH          0x00000002
#define PDB_FPO_DFL_IN_BLOCK    0x00000004
    DWORD       flags;
} PDB_FPO_DATA;

#include "poppack.h"

/* ----------------------------------------------
 * Information used for parsing
 * ---------------------------------------------- */

typedef struct
{
    DWORD  from;
    DWORD  to;
} OMAP_DATA;

struct msc_debug_info
{
    struct module*              module;
    int			        nsect;
    const IMAGE_SECTION_HEADER* sectp;
    int			        nomap;
    const OMAP_DATA*            omapp;
    const BYTE*                 root;
};

/* coff.c */
extern BOOL coff_process_info(const struct msc_debug_info* msc_dbg);

/* ===================================================
 * The old CodeView stuff (for NB09 and NB11)
 * =================================================== */

#define sstModule      0x120
#define sstTypes       0x121
#define sstPublic      0x122
#define sstPublicSym   0x123
#define sstSymbols     0x124
#define sstAlignSym    0x125
#define sstSrcLnSeg    0x126
#define sstSrcModule   0x127
#define sstLibraries   0x128
#define sstGlobalSym   0x129
#define sstGlobalPub   0x12a
#define sstGlobalTypes 0x12b
#define sstMPC         0x12c
#define sstSegMap      0x12d
#define sstSegName     0x12e
#define sstPreComp     0x12f
#define sstFileIndex   0x133
#define sstStaticSym   0x134

/* overall structure information */
typedef struct OMFSignature
{
    char        Signature[4];
    long        filepos;
} OMFSignature;

typedef struct OMFSignatureRSDS
{
    char        Signature[4];
    GUID        guid;
    DWORD       age;
    CHAR        name[1];
} OMFSignatureRSDS;

typedef struct _CODEVIEW_PDB_DATA
{
    char        Signature[4];
    long        filepos;
    DWORD       timestamp;
    DWORD       age;
    CHAR        name[1];
} CODEVIEW_PDB_DATA, *PCODEVIEW_PDB_DATA;

typedef struct OMFDirHeader
{
    WORD        cbDirHeader;
    WORD        cbDirEntry;
    DWORD       cDir;
    DWORD       lfoNextDir;
    DWORD       flags;
} OMFDirHeader;

typedef struct OMFDirEntry
{
    WORD        SubSection;
    WORD        iMod;
    DWORD       lfo;
    DWORD       cb;
} OMFDirEntry;

/* sstModule subsection */

typedef struct OMFSegDesc
{
    WORD        Seg;
    WORD        pad;
    DWORD       Off;
    DWORD       cbSeg;
} OMFSegDesc;

typedef struct OMFModule
{
    WORD        ovlNumber;
    WORD        iLib;
    WORD        cSeg;
    char        Style[2];
/*
    OMFSegDesc  SegInfo[cSeg];
    p_string    Name;
*/
} OMFModule;

typedef struct OMFGlobalTypes
{
    DWORD       flags;
    DWORD       cTypes;
/*
    DWORD       offset[cTypes];
                types_record[];
*/
} OMFGlobalTypes;

/* sstGlobalPub section */

/* Header for symbol table */
typedef struct OMFSymHash
{
    unsigned short  symhash;
    unsigned short  addrhash;
    unsigned long   cbSymbol;
    unsigned long   cbHSym;
    unsigned long   cbHAddr;
} OMFSymHash;

/* sstSegMap section */

typedef struct OMFSegMapDesc
{
    unsigned short  flags;
    unsigned short  ovl;
    unsigned short  group;
    unsigned short  frame;
    unsigned short  iSegName;
    unsigned short  iClassName;
    unsigned long   offset;
    unsigned long   cbSeg;
} OMFSegMapDesc;

typedef struct OMFSegMap
{
    unsigned short  cSeg;
    unsigned short  cSegLog;
/*    OMFSegMapDesc   rgDesc[0];*/
} OMFSegMap;


/* sstSrcModule section */

typedef struct OMFSourceLine
{
    unsigned short  Seg;
    unsigned short  cLnOff;
    unsigned long   offset[1];
    unsigned short  lineNbr[1];
} OMFSourceLine;

typedef struct OMFSourceFile
{
    unsigned short  cSeg;
    unsigned short  reserved;
    unsigned long   baseSrcLn[1];
    unsigned short  cFName;
    char            Name;
} OMFSourceFile;

typedef struct OMFSourceModule
{
    unsigned short  cFile;
    unsigned short  cSeg;
    unsigned long   baseSrcFile[1];
} OMFSourceModule;
