#include "readDwarf.h"
#include <assert.h>
#include <map>
#include <unordered_map>
#include <array>
#include <windows.h>

#include "PEImage.h"
#include "dwarf.h"
#include "mspdb.h"
extern "C" {
#include "mscvpdb.h"
}

static Location mkInReg(unsigned reg)
{
	Location l;
	l.type = Location::InReg;
	l.reg = reg;
	return l;
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

static Location mkImm(unsigned long long len, byte* ptr)
{
	Location l;
	l.type = Location::Imm;
	l.len = len;
	l.ptr = ptr;
	return l;
}

static Location mkImplPtr(byte* ptr, long long off)
{
	Location l;
	l.type = Location::ImplPtr;
	l.die_ptr = ptr;
	l.die_off = off;
	return l;
}

static const PEImage* img;
static const PEImage* dbgimg;
static bool has_section_at_zero = false;

static Piece* pieces = NULL;
static int num_pieces = 0;

static void addPiece(Location* stack, int stackDepth, unsigned long long size, unsigned long long offset)
{
	num_pieces++;
	Piece* newpieces = (Piece*)realloc(pieces, num_pieces * sizeof(struct Piece));
	if (!newpieces)
	{
		free(pieces);
		pieces = NULL;
		num_pieces = 0;
		__debugbreak();
		exit(1);
		return;
	}
	pieces = newpieces;
	Piece* p = &pieces[num_pieces - 1];
	p->size = size;
	p->offset = offset;

	if (stackDepth == 0)
	{
		p->loc.type = Location::OptOut;
		stack[stackDepth].type = Location::OptOut;
	}
	else
	{
		p->loc = stack[stackDepth - 1];
	}
}

static unsigned long long getAddrByIndex(unsigned index, unsigned long long off, int size)
{
	if (!dbgimg->debug_addr || off + index*size >= dbgimg->debug_addr_length)
		return 0;

	byte* p = (byte*)dbgimg->debug_addr + off + index*size;
	return RDsize(p, size);
}

static DWARF_Attribute findBestLocExpr(const DWARF_Attribute& attr, const CompilationUnitData& cu, unsigned long long pc)
{
	static DWARF_Attribute invalid = { Invalid };

	LOCCursor cursor(cu, attr.sec_off.ptr, attr.sec_off.len, attr.sec_off.off);
	LOCEntry entry;
	locListMap_t result;
	while (cursor.readNext(entry))
	{
		if ((entry.beg_offset == entry.end_offset && pc == entry.beg_offset) ||
			(pc >= entry.beg_offset && pc < entry.end_offset))
		{
			return entry.attr;
		}
	}
	return invalid;
}

static Location readPiecedValue(int size, long value_offset)
{
	static Location invalid = { Location::Invalid };
	//TODO: implement simulated read from pieced value
#if 0
	int skipbits = 8 * value_offset;
	unsigned long typelen = 8 * size;
	unsigned int buffsize = 0;
	//TODO: remove buffer, only simulate copy below
	byte* buffer = NULL;
	//TODO: implement bitfields
	//if (loc.bitsize) {
	//	skipbits += loc.bitpos;
	//	typelen = loc.bitsize;
	//}

	long offset = 0;

	for (int i = 0; i < num_pieces && offset < typelen; i++)
	{
		Piece *p = &pieces[i];
		unsigned int this_size, this_size_bits;
		long dest_offset_bits, source_offset_bits, source_offset;
		const byte *intermediate_buffer;

		/* Compute size, source, and destination offsets for copying, in
		bits.  */
		this_size_bits = p->size;
		if (skipbits > 0 && skipbits >= this_size_bits)
		{
			skipbits -= this_size_bits;
			continue;
		}
		if (skipbits > 0)
		{
			dest_offset_bits = 0;
			source_offset_bits = skipbits;
			this_size_bits -= skipbits;
			skipbits = 0;
		}
		else
		{
			dest_offset_bits = offset;
			source_offset_bits = 0;
		}

		if (this_size_bits > typelen - offset)
			this_size_bits = typelen - offset;

		this_size = (this_size_bits + source_offset_bits % 8 + 7) / 8;
		source_offset = source_offset_bits / 8;
		if (buffsize < this_size)
		{
			buffsize = this_size;
			buffer = (byte*)realloc(buffer, buffsize);
		}
		intermediate_buffer = buffer;

		//TODO: append simulated copied bits to new location
		switch (p->loc.type)
		{
		case Location::InReg:
		{
			Location partialReg = p->loc;
			partialReg.value_offset = source_offset;
		}	break;
		case Location::Abs:
		case Location::RegRel:
		{
			Location mem = p->loc;
			mem.off += source_offset;
		}	break;
		case Location::InStack:
		{
		}	break;
		case Location::Imm:
		{
		}	break;
		case Location::ImplPtr:
			break;
		case Location::OptOut:
		{
		}	break;
		default:
			assert(false);
			break;
		}

		offset += this_size_bits;
	}
#endif
	return invalid;
}

static const Location decodeConstValueExpr(const DWARF_Attribute& attr, const CompilationUnitData& cu, unsigned long long* len)
{
	static Location invalid = { Location::Invalid };

	if (attr.type == Invalid)
		return invalid;

	Location result = invalid;
	switch (attr.type)
	{
	case Addr:
		result = mkAbs(attr.addr);
		*len = cu.header->addrSize();
		break;
	case String:
		result = mkImm(strlen(attr.string), (byte*)attr.string);
		*len = result.len;
		break;
	case Block:
	case ExprLoc:
		result = mkImm(attr.block.len, attr.block.ptr);
		*len = result.len;
		break;
	case Const:
		result = mkAbs(attr.cons);
		*len = 8;  //TODO: use actual size of DW_FORM_*data*
		break;
	default:
		return result; // convert unsupported to opt out
	}
	return result;
}

static const Location indirectPiecedLocation(const CompilationUnitData& cu, int size, const FrameInfoData* frame, long value_offset)
{
	static Location invalid = { Location::Invalid };
	static Location optout = { Location::OptOut };
	int bitlen = 8 * size;
	int bitoffset = 8 * value_offset;
	//TODO: implement bitfields
	//if (loc.bitsize)
	//	bitoffset += loc.bitpos;

	if (num_pieces <= 0 || bitlen <= 0)
		return invalid;

	Piece* piece = NULL;
	for (int i = 0; i < num_pieces && bitlen > 0; i++)
	{
		Piece *p = &pieces[i];
		assert(p->size <= INT_MAX);
		int piecesize = (int)p->size;

		if (bitoffset > 0)
		{
			if (bitoffset >= piecesize)
			{
				bitoffset -= piecesize;
				continue;
			}

			bitlen -= piecesize - bitoffset;
			bitoffset = 0;
		}
		else
			bitlen -= piecesize;

		if (!p->loc.is_implptr())
			return invalid;

		if (bitlen != 0)
		{
			assert(false && "Invalid use of DW_OP_GNU_implicit_pointer");
			return invalid;
		}

		piece = p;
		break;
	}

	assert(piece);
	//TODO: as long as readPiecedValue can only be simulated, we can skip it 
	long long valueoffset = 0; // try_extract_signed_int(readPiecedValue(size, value_offset));
	valueoffset += piece->loc.die_off;

	byte* ptr = piece->loc.die_ptr;
	DIECursor cursor = findCompilationUnitChildCursor(ptr);
	DWARF_InfoData id;
	cursor.readNext(id);
	if (id.location.type != Invalid)
	{
		if (id.location.type == LocListPtr)
		{
			assert(frame != NULL);
			id.location = findBestLocExpr(id.location, cursor.cu, frame->pc);
			//TODO: maybe get all locations, so the caller can decide?
			//auto locs = decodeLocationList(id.location, cursor.cu, frame, valueoffset);
		}

		if (id.location.type == Block || id.location.type == ExprLoc)
		{
			return decodeLocation(id.location, cursor.cu, frame, 0, valueoffset);
		}
		else
		{
			assert(false);
			return invalid;
		}
	}

	unsigned long long len;
	Location result = decodeConstValueExpr(id.const_value, cursor.cu, &len);
	if (result.is_invalid())
		return optout;
	if (valueoffset<0 || (unsigned)valueoffset>len) //TODO: check also (valueoffset+target type size)>len
		assert(false);
	switch (result.type)
	{
	case Location::Abs:
		result.off >>= valueoffset * 8;
	case Location::Imm:
		result.ptr += valueoffset;
		result.len -= valueoffset;
	default:
		break;
	}
	return result;
}

static bool checkPiecedSyntheticPointer(int bitoffset, int bitlen, long value_offset)
{
	bitoffset += 8 * value_offset;
	//TODO: implement bitfields
	//if (loc.bitsize)
	//	bit_offset += loc.bitpos;

	for (int i = 0; i < num_pieces && bitlen > 0; i++)
	{
		Piece *p = &pieces[i];
		assert(p->size <= INT_MAX);
		int piecesize = (int)p->size;

		if (bitoffset > 0)
		{
			if (bitoffset >= piecesize)
			{
				bitoffset -= piecesize;
				continue;
			}

			bitlen -= piecesize - bitoffset;
			bitoffset = 0;
		}
		else
			bitlen -= piecesize;

		if (!p->loc.is_implptr())
			return false;
	}

	return true;
}


static void evaluateExpr(Location stack[256], int& stackDepth, const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame, int at);

static void evaluateCallExpr(Location stack[256], int& stackDepth, const FrameInfoData* frame, byte* dieptr)
{
	static Location invalid = { Location::Invalid };

	DIECursor cursor = findCompilationUnitChildCursor(dieptr);
	DWARF_InfoData id;
	if (!cursor.readNext(id))
		return;
	if (id.location.type == Invalid)
		return;

	if (id.location.type == LocListPtr)
	{
		assert(frame != NULL);
		id.location = findBestLocExpr(id.location, cursor.cu, frame->pc);
		if (id.location.type == Invalid)
			return;
		//TODO: maybe get all locations, so the caller can decide?
		//auto locs = decodeLocationList(id.location, cursor.cu, frame);
	}

	assert(id.location.type == Block || id.location.type == ExprLoc);
	evaluateExpr(stack, stackDepth, id.location, cursor.cu, frame, 0);
}

static const CallSiteParam* regLocationToEntryParam(const FrameInfoData* calleeFrame, const Location& regloc, CompilationUnitData* cu)
{
	while (calleeFrame->is_inline())
		calleeFrame = calleeFrame->prev;

	unsigned long long func_addr = calleeFrame->func;
	const FrameInfoData* callerFrame = calleeFrame->prev;
	const CallSiteParam* param = NULL;
	const CallSite* callSite = NULL;
	if (!callerFrame)
	{
		//TODO: check all callsites?
		callSite = findCallSiteForTarget(func_addr);
		if (callSite == NULL)
			return NULL;
	}
	else
	{
		unsigned long long callerpc = callerFrame->pc;
		callSite = getCallSiteForPC(callerpc);
		if (callSite == NULL || func_addr != callSite->getTargetAddr(callerFrame))
			return NULL;
	}

	unsigned i;
	for (i = 0; i < callSite->params.size(); i++)
	{
		param = &callSite->params[i];
		if (param->loc == regloc)
			break;
	}
	if (i == callSite->params.size())
		return NULL;
	*cu = callSite->cu;
	return param;
}

#define return_invalid() \
	do { \
		stack[stackDepth++] = invalid; \
		return; \
	} while (0) \

static void pushRegEntryValue(Location stack[256], int& stackDepth, const FrameInfoData* frame, const Location& regloc, int derefsize = -1)
{
	static Location invalid = { Location::Invalid };

	CompilationUnitData callercu;
	const CallSiteParam* parameter = regLocationToEntryParam(frame, regloc, &callercu);
	if (parameter == NULL)
		return_invalid();
	DWARF_Attribute attr = derefsize == -1 ? parameter->value : parameter->data_value;
	assert(attr.type == Block || attr.type == ExprLoc);
	evaluateExpr(stack, stackDepth, attr, callercu, frame ? frame->prev : NULL, 0);
}

static void evaluateExpr(Location stack[256], int& stackDepth, const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame, int at)
{
	static Location invalid = { Location::Invalid };

#define REQUIRE_COMPOSITION(op) \
	if (p != end && *p != DW_OP_piece && *p != DW_OP_bit_piece) { \
		assert(false); \
		return_invalid(); \
	}

	byte* p = attr.expr.ptr;
	byte* end = attr.expr.ptr + attr.expr.len;
	int stackDepthStart = stackDepth;
	if (at == DW_AT_data_member_location || at == DW_AT_vtable_elem_location)
	{
		stack[stackDepth++] = Location{ Location::Abs, 0, 0 };
		if (at == DW_AT_vtable_elem_location)
			stack[stackDepth++] = Location{ Location::Abs, 0, 0 };
	}
	int relocate_addr = 0; // Offset used to relocate DW_OP_addr and DW_OP_GNU_addr_index arguments

	for (;;)
	{
		if (p >= end)
			break;
		if (stackDepth >= 256)
		{
			assert(false);
			break;
		}

		int op = *p++;
		if (op == 0)
			break;

		switch (op)
		{
		case DW_OP_const1u: stack[stackDepth++] = mkAbs(*p++); break;
		case DW_OP_const2u: stack[stackDepth++] = mkAbs(RD2(p)); break;
		case DW_OP_const4u: stack[stackDepth++] = mkAbs(RD4(p)); break;
		case DW_OP_const8u: stack[stackDepth++] = mkAbs(RD8(p)); break;
		case DW_OP_const1s: stack[stackDepth++] = mkAbs((char)*p++); break;
		case DW_OP_const2s: stack[stackDepth++] = mkAbs((short)RD2(p)); break;
		case DW_OP_const4s: stack[stackDepth++] = mkAbs((int)RD4(p)); break;
		case DW_OP_const8s: stack[stackDepth++] = mkAbs((long long)RD8(p)); break;
		case DW_OP_constu:  stack[stackDepth++] = mkAbs(LEB128<unsigned long long>(p)); break;
		case DW_OP_consts:  stack[stackDepth++] = mkAbs(SLEB128<long long>(p)); break;

		case DW_OP_lit0:  case DW_OP_lit1:  case DW_OP_lit2:  case DW_OP_lit3:
		case DW_OP_lit4:  case DW_OP_lit5:  case DW_OP_lit6:  case DW_OP_lit7:
		case DW_OP_lit8:  case DW_OP_lit9:  case DW_OP_lit10: case DW_OP_lit11:
		case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14: case DW_OP_lit15:
		case DW_OP_lit16: case DW_OP_lit17: case DW_OP_lit18: case DW_OP_lit19:
		case DW_OP_lit20: case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23:
		case DW_OP_lit24: case DW_OP_lit25: case DW_OP_lit26: case DW_OP_lit27:
		case DW_OP_lit28: case DW_OP_lit29: case DW_OP_lit30: case DW_OP_lit31:
			stack[stackDepth++] = mkAbs(op - DW_OP_lit0);
			break;

		case DW_OP_breg0:  case DW_OP_breg1:  case DW_OP_breg2:  case DW_OP_breg3:
		case DW_OP_breg4:  case DW_OP_breg5:  case DW_OP_breg6:  case DW_OP_breg7:
		case DW_OP_breg8:  case DW_OP_breg9:  case DW_OP_breg10: case DW_OP_breg11:
		case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
		case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
		case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
		case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
		case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31:
			stack[stackDepth++] = mkRegRel(op - DW_OP_breg0, SLEB128<long long>(p));
			break;
		case DW_OP_bregx:
		{
			unsigned reg = LEB128<unsigned>(p);
			stack[stackDepth++] = mkRegRel(reg, SLEB128<long long>(p));
		}   break;


		case DW_OP_abs: case DW_OP_neg: case DW_OP_not: case DW_OP_plus_uconst:
		{
			Location& op1 = stack[stackDepth - 1];
			if (!op1.has_stackval())
			{
				if (op != DW_OP_plus_uconst || !op1.need_deref())
					return_invalid();
				op1.valoff += LEB128<unsigned long long>(p);
				break;
			}
			switch (op)
			{
			case DW_OP_abs:   op1.off = abs(op1.off); break;
			case DW_OP_neg:   op1.off = -op1.off; break;
			case DW_OP_not:   op1.stackval = ~op1.stackval; break;
			case DW_OP_plus_uconst:	op1.stackval += LEB128<unsigned long long>(p); break;
			}
		}   break;

		case DW_OP_plus:  // op2 + op1
		{
			Location& op1 = stack[stackDepth - 1];
			Location& op2 = stack[stackDepth - 2];
			// Can add only two offsets or a regrel and an offset.
			if (op2.has_stackval() && op1.has_stackval())
			{
				if (op2.is_regrel() && (op1.is_abs() || op1.is_implptr()))
					op2 = mkRegRel(op2.reg, op2.off + op1.stackval);
				else if ((op2.is_abs() || op2.is_implptr()) && op1.is_regrel())
					op2 = mkRegRel(op1.reg, op2.stackval + op1.off);
				else if (!op2.is_regrel() && !op1.is_regrel())
					op2 = mkAbs(op2.stackval + op1.stackval);
				else
					return_invalid();
			}
			else if (op2.need_deref() && op1.is_abs())
				op2.valoff += op1.off;
			else if (op2.is_abs() && op1.need_deref())
			{
				op1.valoff += op2.off;
				op2 = op1;
			}
			else
				return_invalid();
			--stackDepth;
		}   break;

		case DW_OP_minus: // op2 - op1
		{
			Location& op1 = stack[stackDepth - 1];
			Location& op2 = stack[stackDepth - 2];
			if (op2.has_stackval() && op1.has_stackval())
			{
				if (op2.is_regrel() && op1.is_regrel() && op2.reg == op1.reg)
					op2 = mkAbs(op2.off - op1.off); // X - X == 0
				else if (op2.is_regrel() && (op1.is_abs() || op1.is_implptr()))
					op2 = mkRegRel(op2.reg, op2.off - op1.stackval);
				else if ((op2.is_abs() || op2.is_implptr()) && op1.is_regrel())
					return_invalid(); // cannot store (-reg)
				else if (op2.is_abs() && op1.is_abs())
					op2 = mkAbs(op2.off - op1.off);
				else
					return_invalid();
			}
			else if (op2.need_deref() && op1.is_abs())
				op2.valoff -= op1.off;
			else if (op2.is_abs() && op1.need_deref())
				return_invalid(); // cannot store (-op1)
			else
				return_invalid();
			--stackDepth;
		}   break;

		case DW_OP_mul:
		{
			Location& op1 = stack[stackDepth - 1];
			Location& op2 = stack[stackDepth - 2];
			if ((op1.is_abs() && op1.off == 0) || (op2.is_abs() && op2.off == 0))
				op2 = mkAbs(0); // X * 0 == 0
			else if (op1.is_abs() && op2.is_abs())
				op2 = mkAbs(op1.off * op2.off);
			else
				return_invalid();
			--stackDepth;
		}   break;

		case DW_OP_and:
		{
			Location& op1 = stack[stackDepth - 1];
			Location& op2 = stack[stackDepth - 2];
			if ((op1.is_abs() && op1.off == 0) || (op2.is_abs() && op2.off == 0))
				op2 = mkAbs(0); // X & 0 == 0
			else if (op1.is_abs() && op2.is_abs())
				op2 = mkAbs(op1.off & op2.off);
			else
				return_invalid();
			--stackDepth;
		}   break;

		case DW_OP_div: case DW_OP_mod: case DW_OP_shl:
		case DW_OP_shr: case DW_OP_shra: case DW_OP_or:
		case DW_OP_xor:
		case DW_OP_eq:  case DW_OP_ge:  case DW_OP_gt:
		case DW_OP_le:  case DW_OP_lt:  case DW_OP_ne:
		{
			Location& op1 = stack[stackDepth - 1];
			Location& op2 = stack[stackDepth - 2];
			if (!op1.is_abs() || !op2.is_abs()) // can't combine unless both are constants
				return_invalid();
			switch (op)
			{
			case DW_OP_div:   op2.off = op2.off / op1.off; break;
			case DW_OP_mod:   op2.off = op2.off % op1.off; break;
			case DW_OP_shl:   op2.off = op2.off << op1.off; break;
			case DW_OP_shr:   op2.off = op2.off >> op1.off; break;
			case DW_OP_shra:  op2.off = op2.off >> op1.off; break;
			case DW_OP_or:    op2.off = op2.off | op1.off; break;
			case DW_OP_xor:   op2.off = op2.off ^ op1.off; break;
			case DW_OP_eq:    op2.off = op2.off == op1.off; break;
			case DW_OP_ge:    op2.off = op2.off >= op1.off; break;
			case DW_OP_gt:    op2.off = op2.off > op1.off; break;
			case DW_OP_le:    op2.off = op2.off <= op1.off; break;
			case DW_OP_lt:    op2.off = op2.off < op1.off; break;
			case DW_OP_ne:    op2.off = op2.off != op1.off; break;
			}
			--stackDepth;
		}   break;

		case DW_OP_fbreg:
		{
			if (!frame)
				return_invalid();

			Location loc;
			const Location& base = frame->base;
			if (base.is_inreg()) // ok in frame base specification, per DWARF4 spec #3.3.5
				loc = mkRegRel(base.reg, SLEB128<long long>(p));
			else if (base.is_regrel())
				loc = mkRegRel(base.reg, base.off + SLEB128<long long>(p));
			else
				return_invalid();
			stack[stackDepth++] = loc;
		}   break;

		case DW_OP_dup:   stack[stackDepth] = stack[stackDepth - 1]; stackDepth++; break;
		case DW_OP_drop:  --stackDepth; break;
		case DW_OP_over:  stack[stackDepth] = stack[stackDepth - 2]; stackDepth++; break;
		case DW_OP_pick: { byte offset = *p++; stack[stackDepth] = stack[stackDepth - (1 + offset)]; stackDepth++; } break;
		case DW_OP_swap: { Location tmp = stack[stackDepth - 1]; stack[stackDepth - 1] = stack[stackDepth - 2]; stack[stackDepth - 2] = tmp; } break;
		case DW_OP_rot: { Location tmp = stack[stackDepth - 1]; stack[stackDepth - 1] = stack[stackDepth - 2]; stack[stackDepth - 2] = stack[stackDepth - 3]; stack[stackDepth - 3] = tmp; } break;

		case DW_OP_addr:
		{
			unsigned long long offset = RDsize(p, cu.header->addrSize());
			/* Some versions of GCC emit DW_OP_addr before
			DW_OP_GNU_push_tls_address.  In this case the value is an
			index, not an address.  We don't support things like
			branching between the address and the TLS op.  */
			if (p >= end || *p != DW_OP_GNU_push_tls_address)
				offset += relocate_addr;
			stack[stackDepth++] = mkAbs(offset);
		}	break;
		case DW_OP_GNU_const_index:
		case DW_OP_GNU_addr_index:
		{
			unsigned index = LEB128<unsigned>(p);
			unsigned long long offset = getAddrByIndex(index, cu.addr_base, cu.header->addrSize());
			if (op == DW_OP_GNU_addr_index)
				offset += relocate_addr;
			stack[stackDepth++] = mkAbs(offset);
		}	break;
		case DW_OP_GNU_push_tls_address:
		{
			Location& op1 = stack[stackDepth - 1];
			unsigned long long off = op1.off;
			//TODO:
			//off = getTlsAddr(off);
			op1 = mkAbs(off);
		}	break;

		case DW_OP_skip:
		{
			unsigned off = RD2(p);
			p += off;
		}   break;

		case DW_OP_bra:
		{
			Location& op1 = stack[stackDepth - 1];
			if (!op1.is_abs())
				return_invalid();
			unsigned off = RD2(p);
			if (op1.off != 0)
			{
				p += off;
			}
			--stackDepth;
		}   break;

		case DW_OP_nop:
			break;

		case DW_OP_call_frame_cfa: // if there is no CFA assume ebp+8/rbp+16
			stack[stackDepth++] = mkRegRel(DW_REG_CFA, 0);
			break;

			/* piece specific stuff */
		case DW_OP_reg0:  case DW_OP_reg1:  case DW_OP_reg2:  case DW_OP_reg3:
		case DW_OP_reg4:  case DW_OP_reg5:  case DW_OP_reg6:  case DW_OP_reg7:
		case DW_OP_reg8:  case DW_OP_reg9:  case DW_OP_reg10: case DW_OP_reg11:
		case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
		case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
		case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
		case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
		case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
			if (p != end  &&
				*p != DW_OP_piece &&
				*p != DW_OP_bit_piece &&
				*p != DW_OP_GNU_uninit) {
				assert(false);
				return_invalid();
			}
			stack[stackDepth++] = mkInReg(op - DW_OP_reg0);
			break;
		case DW_OP_regx:
			stack[stackDepth++] = mkInReg(LEB128<unsigned>(p));
			REQUIRE_COMPOSITION(DW_OP_regx);
			break;

		case DW_OP_GNU_regval_type:
		{
			unsigned reg = (unsigned)LEB128<unsigned>(p);
			byte* type_die = (byte*)cu.header + LEB128<unsigned long long>(p);
			stack[stackDepth++] = mkInReg(reg);
		}	break;

		case DW_OP_implicit_value:
		{
			unsigned long long len = LEB128<unsigned long long>(p);
			if (p + len > end) {
				assert(false);
				return_invalid();
			}
			stack[0] = mkImm(len, p);
			stackDepth = 1;
			p += len;
			REQUIRE_COMPOSITION(DW_OP_implicit_value);
		}	break;
		case DW_OP_stack_value:
		{
			Location& op1 = stack[stackDepth - 1];
			// for now only real values on stack are usable
			//TODO: implement better location abstraction for reg access,
			//but not for DW_OP_implicit_value, it never results in a stack value
			if (op1.has_stackval())
				op1.type |= Location::InStack;
			else if (op1.is_inreg())
			{
				op1.type = Location::RegRel | Location::InStack;
				op1.off = 0;
			}
			else if (op1.need_deref())
				op1.type |= Location::InStack;
			else
				return_invalid();
			REQUIRE_COMPOSITION(DW_OP_stack_value);
		}	break;
		case DW_OP_GNU_implicit_pointer:
		{
			/*
			This is a new GNU extension to DWARF that lets debuginfo refer to a synthetic pointer that
			points to content which itself is computed via some DWARF expressions.
			*/
			byte* ptr = (byte*)dbgimg->debug_info + RDsize(p, cu.header->refSize());
			long long off = SLEB128<long long>(p);
			stack[stackDepth++] = mkImplPtr(ptr, off);
			REQUIRE_COMPOSITION(DW_OP_GNU_implicit_pointer);
		}	break;
		case DW_OP_piece:
		{
			unsigned long long size = LEB128<unsigned long long>(p);
			addPiece(stack + stackDepthStart, stackDepth - stackDepthStart, 8 * size, 0);
			if ((stackDepth - stackDepthStart) > 0)
				--stackDepth;
			assert(stackDepth >= 0);
			stack[stackDepth].type = Location::Invalid;
		}	break;
		case DW_OP_bit_piece:
		{
			unsigned long long size = LEB128<unsigned long long>(p);
			unsigned long long offset = LEB128<unsigned long long>(p);
			addPiece(stack + stackDepthStart, stackDepth - stackDepthStart, size, offset);
			if ((stackDepth - stackDepthStart) > 0)
				--stackDepth;
			assert(stackDepth >= 0);
			stack[stackDepth].type = Location::Invalid;
		}	break;
		case DW_OP_GNU_uninit:
			if (p != end) {
				assert(false);
				return_invalid(); // must be last value
			}
			break;

		case DW_OP_call2:	evaluateCallExpr(stack, stackDepth, frame, (byte*)cu.header + RD2(p)); break;
		case DW_OP_call4:	evaluateCallExpr(stack, stackDepth, frame, (byte*)cu.header + RD4(p)); break;

		case DW_OP_deref:
		case DW_OP_deref_size:
		case DW_OP_GNU_deref_type:
		{
			int addr_size = (op == DW_OP_deref ? cu.header->addrSize() : *p++);
			Location& op1 = stack[stackDepth - 1];
			if (!op1.has_stackval())
				return_invalid();	//TODO: implement better location abstraction for reg access

			//struct type *type;
			if (op == DW_OP_GNU_deref_type)
			{
				byte* type_die = (byte*)cu.header + LEB128<unsigned long long>(p);
				//type = get_base_type(type_die, 0);
			}
			//else
			//	type = address_type;

			// gdb derefences directly
			//byte* addr = img->RVA<byte>(op1.stackval - img->getImageBase(), 1);
			///* If the size of the object read from memory is different
			//from the type length, we need to zero-extend it.  */
			//op1 = mkAbs(RDsize(addr, addr_size));

			// use abstract representation, so the un-derefenced location can be used later
			op1.type |= Location::Deref;
			op1.valoff = 0; // offset to add to the dereferenced address starts with zero
			op1.refsize = addr_size;
			//TODO: store type
		}	break;

		case DW_OP_GNU_entry_value:
		{
			if (!frame)
				return_invalid();
			unsigned long long len = LEB128<unsigned long long>(p);
			if (p + len > end)
				return_invalid();

			DWARF_Attribute attr;
			attr.type = Block;
			attr.block.len = len;
			attr.block.ptr = p;
			Location loc = decodeLocation(attr, cu, frame, at, 0);
			p += len;
			if (loc.is_inreg())
			{
				pushRegEntryValue(stack, stackDepth, frame, loc, -1);
			}
			else if (loc.need_deref() && loc.off == 0)
			{
				pushRegEntryValue(stack, stackDepth, frame, mkInReg(loc.reg), loc.refsize);
			}
			else
				return_invalid();

		}	break;

		case DW_OP_GNU_parameter_ref:
		{
			if (!frame)
				return_invalid();
			unsigned off = RD4(p);
			pushRegEntryValue(stack, stackDepth, frame, mkAbs(off), -1);
		}	break;

		case DW_OP_push_object_address:
		case DW_OP_form_tls_address:
		case DW_OP_call_ref:
		default:
			return_invalid();
		}
	}

	assert((stackDepth - stackDepthStart) == 1 || stack[0].type == Location::Invalid ||
		at == DW_AT_vtable_elem_location);

	/* To simplify our main caller, if the result is an implicit
	pointer, then make a pieced value.  This is ok because we can't
	have implicit pointers in contexts where pieces are invalid.  */
	if (stack[0].is_implptr())
		addPiece(stack + stackDepthStart, stackDepth - stackDepthStart, 8 * cu.header->addrSize(), 0);
}

Location decodeLocation(const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame, int at, long long offset)
{
	static Location invalid = { Location::Invalid };

	if (attr.type == Const)
		return mkAbs(attr.cons);

	if (attr.type != ExprLoc && attr.type != Block) // same memory layout
		return invalid;

	Location stack[256] = { Location::Invalid };
	int stackDepth = 0;
	Piece* oldpieces = pieces;
	pieces = NULL;
	int oldnum_pieces = num_pieces;
	num_pieces = 0;

	evaluateExpr(stack, stackDepth, attr, cu, frame, at);

	Location loc;
	if (num_pieces > 0) {
		// shortcut for impl. pointer so caller can compare to parent DIEs
		// TODO: if there is no parent DIE, try to decode it
		if (num_pieces == 1 && pieces[0].loc.is_implptr())
			loc = pieces[0].loc;
		else
		{
			//TODO: use actual size
			int size = cu.header->addrSize();
			if (checkPiecedSyntheticPointer(0, size * 8, (long)offset))
				loc = indirectPiecedLocation(cu, size, frame, (long)offset);
			else
				loc = readPiecedValue(size, (long)offset);
		}

		free(pieces);
		pieces = oldpieces;
		num_pieces = oldnum_pieces;
	}
	else
	{
		pieces = oldpieces;
		num_pieces = oldnum_pieces;

		loc = stack[stackDepth - 1];
		switch (loc.type)
		{
		case Location::InReg:
			assert(offset == 0); // no offset for pointer to register;
			break;
		case Location::Abs:
		case Location::RegRel:
			loc.off += offset;
			break;
		case Location::InStack | Location::Abs:
			if (offset > sizeof(loc.stackval))
			{
				assert(false);
				return invalid;
			}
			loc.stackval >>= offset * 8;
			loc.valoff = 0;
			break;
		case Location::InStack | Location::RegRel:
			loc.valoff = offset;
			break;
		case Location::Imm:
			if (offset > sizeof(loc.len))
			{
				assert(false);
				return invalid;
			}
			loc.ptr += offset;
			loc.len -= offset;
			break;
		case Location::Deref | Location::RegRel:
		case Location::Deref | Location::Abs:
			loc.valoff += offset;
			break;
		case Location::InStack | Location::Deref | Location::RegRel:
		case Location::InStack | Location::Deref | Location::Abs:
			assert(offset == 0); // there can't be an offset to the value bits
			break;
		case Location::OptOut:
			break;
		case Location::Invalid:
			return invalid;
		case Location::ImplPtr:
		default:
			assert(false);
			return invalid;
		}
	}

	return loc;
}

locListMap_t decodeLocationList(const DWARF_Attribute& attr, const CompilationUnitData& cu, const FrameInfoData* frame, long long valoff)
{
	LOCCursor cursor(cu, attr.sec_off.ptr, attr.sec_off.len, attr.sec_off.off);
	LOCEntry entry;
	locListMap_t result;
	while (cursor.readNext(entry))
	{
		pcRange_t key = { entry.beg_offset, entry.end_offset };
		locListMap_t::_Pairib itadded = result.insert(std::make_pair(key, decodeLocation(entry.attr, cu, frame, 0, valoff)));
		assert(itadded.second);
	}
	return result;
}

bool decodeRanges(const DWARF_Attribute& attr, pcRange_t* minmax, const CompilationUnitData& cu, std::vector<pcRange_t>* ranges)
{
	if (attr.type != RangeListPtr)
		return false;
	if ((attr.sec_off.off + cu.ranges_base) >= attr.sec_off.len)
		return false;

	const unsigned int addr_size = cu.header->addrSize();
	const unsigned long long mask = addr_size == 8 ? ULLONG_MAX : ULONG_MAX;
	unsigned long long base = cu.base_address;
	byte* r = (byte*)attr.sec_off.ptr + attr.sec_off.off + cu.ranges_base;
	byte* rend = (byte*)attr.sec_off.ptr + attr.sec_off.len;

	bool lowset = false;
	unsigned long long low, high;
	while (r < rend)
	{
		pcRange_t range;
		range.pclo = RDsize(r, addr_size);
		range.pchi = RDsize(r, addr_size);
		//off += 2 * addr_size;

		/* An end of list marker is a pair of zero addresses.  */
		if (range.pclo == 0 && range.pchi == 0)
			break;

		if ((range.pclo & mask) == mask)
		{
			/* If we found the largest possible address, then
			read the base address.  */
			base = range.pchi;
			continue;
		}

		if (range.pclo > range.pchi)
			/* Inverted range entries are invalid.  */
			return false;

		/* Empty range entries have no effect.  */
		if (range.pclo == range.pchi)
			continue;

		range.pclo += base;
		range.pchi += base;

		/* A not-uncommon case of bad debug info.
		Don't pollute the addrmap with bad data.  */
		if (range.pclo == 0 && !has_section_at_zero)
		{
			//TODO: ignore it or handle the case?
			continue;
		}


		if (ranges != NULL)
			ranges->push_back(range);

		if (!lowset)
		{
			low = range.pclo;
			high = range.pchi;
			lowset = true;
		}
		else
		{
			if (range.pclo < low)
				low = range.pclo;
			if (range.pchi > high)
				high = range.pchi;
		}
	}

	if (!lowset)
		/* If the first entry is an end-of-list marker, the range
		describes an empty scope, i.e. no instructions.  */
		return false;

	if (minmax)
	{
		minmax->pclo = low;
		minmax->pchi = high;
	}
	return true;
}

// declare hasher for pair<T1,T2>
namespace std
{
	template<typename T1, typename T2>
	struct hash<std::pair<T1, T2>>
	{
		size_t operator()(const std::pair<T1, T2>& t) const
		{
			return std::hash<T1>()(t.first) ^ std::hash<T2>()(t.second);
		}
	};
}

typedef std::unordered_map<unsigned, byte*> abbrevCodeMap_t;
typedef std::unordered_map<unsigned long long, std::pair<byte*, abbrevCodeMap_t>> abbrevMap_t;
typedef std::map<unsigned long long, DIECursor> cuDataMap_t;
typedef std::unordered_map<unsigned long long, CallSite> callSiteMap_t;

static abbrevMap_t abbrevMap;
static cuDataMap_t cuCursorMap;
static callSiteMap_t callSiteMap;

const DIECursor DIECursor::Invalid;

void DIECursor::setContext(const PEImage* img_, const PEImage* dbgimg_)
{
	img = img_;
	dbgimg = dbgimg_;
	has_section_at_zero = img ? img->hasSectionAtZeroVMA() : false;
	abbrevMap.clear();
	cuCursorMap.clear();
}

DIECursor::DIECursor(const DWARF_CompilationUnit* cu_)
{
	cu.header = cu_;
	cu.base_address = 0;
	cu.addr_base = 0;
	cu.language = CompilationUnitData::language_unknown;
	if (cu_)
		ptr = (byte*)cu_ + (cu_->isDWARF64() ? sizeof(DWARF_CompilationUnit::hdr64) : sizeof(DWARF_CompilationUnit::hdr32));
	else
		ptr = 0;
	lastptr = 0;
	level = 0;
	hasChild = false;
	sibling = 0;
	parentCursor = 0;
}

bool DIECursor::isInvalid()
{
	return level == -1;
}

void DIECursor::gotoSibling()
{
	if (sibling)
	{
		// use sibling pointer, if available
		ptr = sibling;
		hasChild = false;
	}
	else if (hasChild)
	{
		int currLevel = level;
		level = currLevel + 1;
		hasChild = false;

		DWARF_InfoData dummy;
		// read untill we pop back to the level we were at
		while (level > currLevel)
			readNext(dummy, true /* stop at every level decrease */);
	}
}

void DIECursor::gotoSubtree(byte * childptr, const DIECursor* parent)
{
	if (hasChild)
	{
		level = 0;
		hasChild = false;
		parentCursor = parent;
		if (childptr)
		{
			if (!sibling || (childptr >= ptr && childptr < sibling))
				ptr = childptr;
			else
				level = -1; //invalid childptr
		}
	}
	else // Return invalid cursor
	{
		level = -1;
	}
}

bool DIECursor::readSibling(DWARF_InfoData& id, bool stopAtNull)
{
	gotoSibling();
	return readNext(id, stopAtNull);
}

DIECursor DIECursor::getSubtreeCursor(byte* childptr) const &
{
	DIECursor subtree = *this;
	subtree.gotoSubtree(childptr, this);
	return subtree;
}

DIECursor&& DIECursor::getSubtreeCursor(byte * childptr) &&
{
	gotoSubtree(childptr);
	return std::move(*this);
}

DIECursor DIECursor::getParentCursor() const
{
	if (parentCursor && parentCursor != this) // RVO can cause parent to point to itself
	{
		DIECursor parent = *parentCursor;
		parent.ptr = parent.lastptr; // ptr already at child, so step back to last DIE
		return parent;
	}
	else // Return invalid cursor
	{
		DIECursor parent = *this;
		parent.hasChild = false;
		parent.level = -1;
		return parent;
	}
}

bool DIECursor::readNext(DWARF_InfoData& id, bool stopAtNull, bool skipSpec)
{
	id.clear();

	if (hasChild)
		++level;

	for (;;)
	{
		if (level == -1)
			return false; // we were already at the end of the subtree

		if (ptr >= ((byte*)cu.header + cu.header->getLength()))
			return false; // root of the tree does not have a null terminator, but we know the length

		lastptr = ptr;
		id.entryPtr = ptr;
		id.entryOff = ptr - (byte*)cu.header;
		id.code = LEB128<unsigned>(ptr);
		if (id.code == 0)
		{
			--level; // pop up one level
			if (stopAtNull)
			{
				hasChild = false;
				return false;
			}
			continue; // read the next DIE
		}

		break;
	}

	byte* abbrev = getDWARFAbbrev(cu.header->getAbbrevOffset(), id.code);
	assert(abbrev);
	if (!abbrev)
		return false;

	id.abbrev = abbrev;
	static_assert(DW_TAG_hi_user <= USHRT_MAX, "DIE tag is bigger than unsigned short");
	id.tag = LEB128<unsigned short>(abbrev);
	id.hasChild = *abbrev++;

	unsigned attr, form;
	for (;;)
	{
		attr = LEB128<unsigned>(abbrev);
		assert(attr < DW_AT_hi_user);
		if (attr >= DW_AT_hi_user)
			return false;
		form = LEB128<unsigned>(abbrev);

		if (attr == 0 && form == 0)
			break;

		while (form == DW_FORM_indirect)
			form = LEB128<unsigned>(ptr);

		DWARF_Attribute a;
		switch (form)
		{
		case DW_FORM_addr:           a.type = Addr; a.addr = RDsize(ptr, cu.header->addrSize()); break;
		case DW_FORM_GNU_addr_index: a.type = Addr; a.addr = getAddrByIndex(LEB128<unsigned>(ptr), cu.addr_base, cu.header->addrSize()); break;
		case DW_FORM_block:          a.type = Block; a.block.len = LEB128<unsigned long long>(ptr); a.block.ptr = ptr; ptr += a.block.len; break;
		case DW_FORM_block1:         a.type = Block; a.block.len = *ptr++;      a.block.ptr = ptr; ptr += a.block.len; break;
		case DW_FORM_block2:         a.type = Block; a.block.len = RD2(ptr);   a.block.ptr = ptr; ptr += a.block.len; break;
		case DW_FORM_block4:         a.type = Block; a.block.len = RD4(ptr);   a.block.ptr = ptr; ptr += a.block.len; break;
		case DW_FORM_data1:          a.type = Const; a.cons = *ptr++; break;
		case DW_FORM_data2:          a.type = Const; a.cons = RD2(ptr); break;
		case DW_FORM_data4:          a.type = Const; a.cons = RD4(ptr); break;
		case DW_FORM_data8:          a.type = Const; a.cons = RD8(ptr); break;
		case DW_FORM_sdata:          a.type = Const; a.cons = SLEB128<long long>(ptr); break;
		case DW_FORM_udata:          a.type = Const; a.cons = LEB128<unsigned long long>(ptr); break;
		case DW_FORM_string:         a.type = String; a.string = (const char*)ptr; ptr += strlen(a.string) + 1; break;
		case DW_FORM_strp:           a.type = String; a.string = (const char*)(dbgimg->debug_str + RDsize(ptr, cu.header->refSize())); break;
		case DW_FORM_flag:           a.type = Flag; a.flag = (*ptr++ != 0); break;
		case DW_FORM_flag_present:   a.type = Flag; a.flag = true; break;
		case DW_FORM_ref1:           a.type = Ref; a.ref = (byte*)cu.header + *ptr++; break;
		case DW_FORM_ref2:           a.type = Ref; a.ref = (byte*)cu.header + RD2(ptr); break;
		case DW_FORM_ref4:           a.type = Ref; a.ref = (byte*)cu.header + RD4(ptr); break;
		case DW_FORM_ref8:           a.type = Ref; a.ref = (byte*)cu.header + RD8(ptr); break;
		case DW_FORM_ref_udata:      a.type = Ref; a.ref = (byte*)cu.header + LEB128<unsigned long long>(ptr); break;
		case DW_FORM_GNU_ref_alt:
		case DW_FORM_ref_addr:
		{
			int size = cu.header->getVersion() == 2 && form != DW_FORM_GNU_ref_alt ?
				cu.header->addrSize() : cu.header->refSize();
			a.type = Ref; a.ref = (byte*)dbgimg->debug_info + RDsize(ptr, size);
		}	break;
		case DW_FORM_ref_sig8:       a.type = RefSig; a.cons = RD8(ptr); break; // it's a 8 byte MD5 signature for type references
		case DW_FORM_exprloc:        a.type = ExprLoc; a.expr.len = LEB128<unsigned long long>(ptr); a.expr.ptr = ptr; ptr += a.expr.len; break;
		case DW_FORM_sec_offset:     a.type = Const; a.cons = RDsize(ptr, cu.header->refSize()); break;
		case DW_FORM_indirect:
		default: assert(false && "Unsupported DWARF attribute form"); return false;
		}


		if (form == DW_FORM_sec_offset || (cu.header->getVersion() < 4 &&
			(form == DW_FORM_data4 || form == DW_FORM_data8)))
		{
			switch (attr)
			{
			case DW_AT_stmt_list:
				a.type = LinePtr;
				a.sec_off.off = a.cons;
				a.sec_off.ptr = (byte*)dbgimg->debug_line;
				a.sec_off.len = dbgimg->debug_line_length;
				break;
			case DW_AT_location:
			case DW_AT_string_length:
			case DW_AT_return_addr:
			case DW_AT_data_member_location:
			case DW_AT_frame_base:
			case DW_AT_segment:
			case DW_AT_static_link:
			case DW_AT_use_location:
			case DW_AT_vtable_elem_location:
				a.type = LocListPtr;
				a.sec_off.off = a.cons;
				a.sec_off.ptr = (byte*)dbgimg->debug_loc;
				a.sec_off.len = dbgimg->debug_loc_length;
				break;
			case DW_AT_macro_info:
				a.type = MacPtr;
				a.sec_off.off = a.cons;
				a.sec_off.ptr = (byte*)dbgimg->debug_macinfo;
				a.sec_off.len = dbgimg->debug_macinfo_length;
				break;
			case DW_AT_start_scope:
			case DW_AT_ranges:
				a.type = RangeListPtr;
				a.sec_off.off = a.cons;
				a.sec_off.ptr = (byte*)dbgimg->debug_ranges;
				a.sec_off.len = dbgimg->debug_ranges_length;
				break;
			default:
				assert(false && "Unsupported DWARF attribute form"); return false;
			}
		}

		static const char* _attr_types[] = { "Invalid", "Addr", "Block", "Const",
			"String", "Flag", "Ref", "RefSig", "ExprLoc", "LinePtr", "LocListPtr", "MacPtr",
			"RangeListPtr"
		};
		switch (attr)
		{
		case DW_AT_sibling:   assert(a.type == Ref); id.sibling = a.ref; break;
		case DW_AT_name:      assert(a.type == String); id.name = a.string; break;
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
			assert(a.type == String); id.linkage_name = a.string; break;
		case DW_AT_comp_dir:  assert(a.type == String); id.dir = a.string; break;
		case DW_AT_producer:  assert(a.type == String); id.producer = a.string; break;
		case DW_AT_low_pc:    assert(a.type == Addr); id.pclo = a.addr; id.haspclo = true; break;
		case DW_AT_high_pc:
			if (a.type == Addr)
				id.pchi = a.addr;
			else if (a.type == Const)
			{
				assert(id.haspclo);
				assert(cu.header->getVersion() >= 4);
				id.pchi = id.pclo + a.cons;
			}
			else
				assert(false);
			id.haspchi = true;
			break;
		case DW_AT_entry_pc:	assert(a.type == Addr); id.pcentry = a.addr; break;
		case DW_AT_type:		assert(a.type == Ref); id.type = a.ref; break;
		case DW_AT_encoding:	assert(a.type == Const && a.cons < DW_ATE_hi_user);
			id.encoding = (byte)a.cons; break;
		case DW_AT_ordering:	assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.ordering = (byte)a.cons; break;
		case DW_AT_visibility:	assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.visible = (byte)a.cons; break;
		case DW_AT_inline:		assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.inlined = (byte)a.cons; break;
		case DW_AT_accessibility:	assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.access = (byte)a.cons; break;
		case DW_AT_calling_convention: assert(a.type == Const && a.cons <= DW_CC_hi_user);
			id.calling_convention = (byte)a.cons; break;
		case DW_AT_virtuality:	assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.virtuality = (byte)a.cons; break;
		case DW_AT_language:	assert(a.type == Const && a.cons < DW_LANG_hi_user);
			id.language = (unsigned short)a.cons; break;
		case DW_AT_external:	assert(a.type == Flag); id.external = a.flag; break;
		case DW_AT_declaration:	assert(a.type == Flag); id.declaration = a.flag; break;
		case DW_AT_prototyped:	assert(a.type == Flag); id.prototyped = a.flag; break;
		case DW_AT_noreturn:	assert(a.type == Flag); id.noreturn = a.flag; break;
		case DW_AT_artificial:	assert(a.type == Flag); id.artificial = a.flag; break;
		case DW_AT_explicit:	assert(a.type == Flag); id.explicit_func = a.flag; break;
		case DW_AT_GNU_deleted:	assert(a.type == Flag); id.deleted = a.flag; break;
		case DW_AT_enum_class:	assert(a.type == Flag); id.enum_class = a.flag; break;
		case DW_AT_GNU_tail_call:			assert(a.type == Flag); id.tail_call = a.flag; break;
		case DW_AT_GNU_all_tail_call_sites: assert(a.type == Flag); id.all_tail_call_sites = a.flag; break;
		case DW_AT_GNU_all_call_sites:		assert(a.type == Flag); id.all_call_sites = a.flag; break;
		case DW_AT_upper_bound:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.upper_bound = a;
			break;
		case DW_AT_lower_bound:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.lower_bound = a;
			break;
		case DW_AT_count:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.count = a;
			break;
		case DW_AT_byte_size:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.byte_size = a;
			break;
		case DW_AT_bit_offset:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.bit_offset = a;
		case DW_AT_bit_size:
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.bit_size = a;
		case DW_AT_stride_size: // = DW_AT_bit_stride
			assert(a.type == Const || a.type == Ref || a.type == ExprLoc);
			id.bit_stride = a;
			break;
		case DW_AT_data_member_location:
			assert(a.type == Const || a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Ref); // dwarf2
			id.member_location = a;
			break;
		case DW_AT_vtable_elem_location:
			assert(a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Ref); // dwarf2
			id.vtable_elem_location = a;
			break;
		case DW_AT_location:
			assert(a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Const); // dwarf2
			id.location = a;
			break;
		case DW_AT_frame_base:
			assert(a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Const); // dwarf2
			id.frame_base = a;
			break;
		case DW_AT_string_length:
			assert(a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Const); // dwarf2
			id.string_length = a;
			break;
		case DW_AT_const_value:
			assert(a.type == Const || a.type == String || a.type == Block);
			id.const_value = a;
			break;
		case DW_AT_return_addr:
			assert(a.type == ExprLoc || a.type == LocListPtr ||
				a.type == Block || a.type == Const); // dwarf2
			id.return_addr = a;
			break;
		case DW_AT_ranges:    assert(a.type == RangeListPtr); id.ranges = a; break;
		case DW_AT_stmt_list: assert(a.type == LinePtr); id.stmt_list = a; break;
		case DW_AT_GNU_addr_base:	assert(a.type == Const); id.addr_base = a.cons; break;
		case DW_AT_GNU_ranges_base:	assert(a.type == Const); id.ranges_base = a.cons; break;
		case DW_AT_containing_type: assert(a.type == Ref); id.containing_type = a.ref; break;
		case DW_AT_object_pointer:	assert(a.type == Ref); id.object_pointer = a.ref; break;
		case DW_AT_abstract_origin:	assert(a.type == Ref); id.abstract_origin = a.ref; break;
		case DW_AT_specification:	assert(a.type == Ref); id.specification = a.ref; break;
		case DW_AT_import:			assert(a.type == Ref); id.import = a.ref; break;
		case DW_AT_default_value:
			if (a.type == Ref)
				id.default_value_ref = a.ref;
			else if (a.type == Const)
				id.default_value = a.cons;
			else if (a.type == Flag)
				id.isdefault = a.flag;
			else
				assert(false);
			break;
		case DW_AT_GNU_call_site_target: id.call_site_target = a; break;
		case DW_AT_GNU_call_site_value: id.call_site = a; break;
		case DW_AT_GNU_call_site_data_value: id.call_site_data = a; break;
		case DW_AT_decl_column: assert(a.type == Const); id.decl_column = (unsigned)a.cons; break;
		case DW_AT_decl_file:	assert(a.type == Const); id.decl_file = (unsigned)a.cons; break;
		case DW_AT_decl_line:	assert(a.type == Const); id.decl_line = (unsigned)a.cons; break;
		case DW_AT_call_column: assert(a.type == Const); id.call_column = (unsigned)a.cons; break;
		case DW_AT_call_file:	assert(a.type == Const); id.call_file = (unsigned)a.cons; break;
		case DW_AT_call_line:	assert(a.type == Const); id.call_line = (unsigned)a.cons; break;

			// extensions
		case DW_AT_go_kind:		assert(a.type == Const && a.cons <= UCHAR_MAX);
			id.go_kind = (byte)a.cons; break;
		case DW_AT_go_key:		assert(a.type == Ref); id.go_key = a.ref; break;
		case DW_AT_go_elem:		assert(a.type == Ref); id.go_elem = a.ref; break;

		default:
		{
			if (attr >= DW_AT_lo_user && attr <= DW_AT_hi_user)
				printf("DWARF extension attribute with id (%d) and type (%s) not decoded.\n", attr, _attr_types[a.type]);
			else
				printf("DWARF attribute with id (%d) and type (%s) not decoded.\n", attr, _attr_types[a.type]);
			break;
		}
		}
	}

	hasChild = id.hasChild != 0;
	sibling = id.sibling;

	if (!skipSpec)
	{
		assert(!(id.specification && id.abstract_origin));
		if (id.specification)
		{
			DIECursor specCursor = findCompilationUnitChildCursor(id.specification);
			DWARF_InfoData idspec;
			specCursor.readNext(idspec);
			assert(idspec.declaration && !idspec.specification);
			//assert seems invalid, combination DW_TAG_member and DW_TAG_variable found in the wild
			//assert(id.tag == idspec.tag);
			id.merge(idspec);
		}
		else if (id.abstract_origin)
		{
			DIECursor origCursor = findCompilationUnitChildCursor(id.abstract_origin);
			DWARF_InfoData idorig;
			origCursor.readNext(idorig);
			assert(id.tag == idorig.tag ||
				(id.tag == DW_TAG_inlined_subroutine && idorig.tag == DW_TAG_subprogram) ||
				(id.tag == DW_TAG_GNU_call_site && idorig.tag == DW_TAG_subprogram) ||
				(id.tag == DW_TAG_GNU_call_site_parameter && idorig.tag == DW_TAG_formal_parameter));
			id.merge(idorig, true);
		}
	}

	return true;
}

bool DIECursor::readAgain(DWARF_InfoData& id, bool skipSpec) const
{
	if (!lastptr)
		return false;
	DIECursor last = *this;
	last.ptr = lastptr;
	return last.readNext(id, true, skipSpec);
}

byte* DIECursor::getDWARFAbbrev(unsigned long long off, unsigned findcode)
{
	if (!dbgimg->debug_abbrev)
		return 0;

	std::pair<byte*, abbrevCodeMap_t>& abbrevCodes = abbrevMap[off];

	abbrevCodeMap_t::iterator it = abbrevCodes.second.find(findcode);
	if (it != abbrevCodes.second.end())
	{
		return it->second;
	}

	byte* p = abbrevCodes.second.empty() ? (byte*)dbgimg->debug_abbrev + off : abbrevCodes.first;
	byte* end = (byte*)dbgimg->debug_abbrev + dbgimg->debug_abbrev_length;
	while (p < end)
	{
		unsigned code = LEB128<unsigned>(p);
		if (code == 0)
			return 0;

		byte* ptag = p;
		unsigned short tag = LEB128<unsigned short>(p);
		byte hasChild = *p++;

		// skip attributes
		unsigned attr, form;
		do
		{
			attr = LEB128<unsigned>(p);
			form = LEB128<unsigned>(p);
		} while (attr || form);

		abbrevCodes.second.insert(std::make_pair(code, ptag));
		abbrevCodes.first = p; // keep track of next code pointer which is not inserted yet
		if (code == findcode)
			return ptag;
	}
	return 0;
}

static enum CompilationUnitData::language get_cu_language(unsigned short lang)
{
	switch (lang)
	{
	case DW_LANG_C89:
	case DW_LANG_C99:
	case DW_LANG_C11:
	case DW_LANG_C:
	case DW_LANG_UPC:
		return CompilationUnitData::language_c;
	case DW_LANG_C_plus_plus:
	case DW_LANG_C_plus_plus_11:
	case DW_LANG_C_plus_plus_14:
		return CompilationUnitData::language_cplus;
	case DW_LANG_D:
		return CompilationUnitData::language_d;
	case DW_LANG_Fortran77:
	case DW_LANG_Fortran90:
	case DW_LANG_Fortran95:
	case DW_LANG_Fortran03:
	case DW_LANG_Fortran08:
		return CompilationUnitData::language_fortran;
	case DW_LANG_Go:
		return CompilationUnitData::language_go;
	case DW_LANG_Mips_Assembler:
		return CompilationUnitData::language_asm;
	case DW_LANG_Java:
		return CompilationUnitData::language_java;
	case DW_LANG_Ada83:
	case DW_LANG_Ada95:
		return CompilationUnitData::language_ada;
	case DW_LANG_Modula2:
		return CompilationUnitData::language_m2;
	case DW_LANG_Pascal83:
		return CompilationUnitData::language_pascal;
	case DW_LANG_ObjC:
		return CompilationUnitData::language_objc;
	case DW_LANG_Cobol74:
	case DW_LANG_Cobol85:
	default:
		return CompilationUnitData::language_minimal;
	}
}

static bool getPCBounds(const DWARF_InfoData& id, pcRange_t& bounds, CompilationUnitData& cu, std::vector<pcRange_t>* ranges)
{
	unsigned long long low = 0;
	unsigned long long high = 0;

	if (id.haspchi)
	{
		if (id.haspclo)
		{
			low = id.pclo;
			high = id.pchi;
		}
		else
			/* Found high w/o low attribute.  */
			return false;

		/* Found consecutive range of addresses.  */
	}
	else
	{
		if (id.ranges.type != Invalid)
		{
			bool is_from_cu = id.tag == DW_TAG_compile_unit;
			/* DW_AT_ranges_base does not apply to DIEs from the DWO skeleton.
			We take advantage of the fact that DW_AT_ranges does not appear
			in DW_TAG_compile_unit of DWO files.  */
			bool need_ranges_base = !is_from_cu;
			unsigned long long ranges_base = cu.ranges_base;
			__try
			{
				if (!need_ranges_base)
					cu.ranges_base = 0;

				/* Value of the DW_AT_ranges attribute is the offset in the
				.debug_ranges section.  */
				pcRange_t minmax;
				if (!decodeRanges(id.ranges, &minmax, cu, is_from_cu ? &cu.ranges : ranges))
				{
					if (is_from_cu)
						cu.ranges.clear(); // make sure that there are only valid ranges
					return false;
				}
				low = minmax.pclo;
				high = minmax.pchi;
			}
			__finally
			{
				if (!need_ranges_base)
					cu.ranges_base = ranges_base;
			}
			/* Found discontinuous range of addresses.  */
		}
	}

	/* read_partial_die has also the strict LOW < HIGH requirement.  */
	if (high <= low)
		return false;

	/* When using the GNU linker, .gnu.linkonce. sections are used to
	eliminate duplicate copies of functions and vtables and such.
	The linker will arbitrarily choose one and discard the others.
	The AT_*_pc values for such functions refer to local labels in
	these sections.  If the section from that file was discarded, the
	labels are not in the output, so the relocs get a value of 0.
	If this is a discarded function, mark the pc bounds as invalid,
	so that GDB will ignore it.  */
	if (low == 0 && !has_section_at_zero)
		return false;

	bounds.pclo = low;
	bounds.pchi = high;
	return true;
}

static void getSubprogramPCBounds(const DIECursor& scope, const DWARF_InfoData& scopeId,
	pcRange_t& bounds, CompilationUnitData& cu)
{
	pcRange_t tempbounds;
	if (getPCBounds(scopeId, tempbounds, cu, NULL))
	{
		bounds.pclo = min(bounds.pclo, tempbounds.pclo);
		bounds.pchi = max(bounds.pchi, tempbounds.pchi);
	}

	/* If the language does not allow nested subprograms (either inside
	subprograms or lexical blocks), we're done.  */
	if (cu.language != CompilationUnitData::language_ada)
		return;

	/* Check all the children of the given DIE.  If it contains nested
	subprograms, then check their pc bounds.  Likewise, we need to
	check lexical blocks as well, as they may also contain subprogram
	definitions.  */
	DIECursor child = scope.getSubtreeCursor();
	DWARF_InfoData id;
	if (!child.readNext(id))
		return;
	do
	{
		if (id.tag == DW_TAG_subprogram
			|| id.tag == DW_TAG_lexical_block)
			getSubprogramPCBounds(child, id, bounds, cu);
	} while (child.readSibling(id));
}

static bool getScopePCBounds(const DIECursor& scope, const DWARF_InfoData& scopeId,
	pcRange_t& bounds, CompilationUnitData& cu)
{
	bounds.pclo = -1;
	bounds.pchi = 0;
	if (getPCBounds(scopeId, bounds, cu, NULL))
		return true;

	DIECursor child = scope.getSubtreeCursor();
	DWARF_InfoData id;
	if (!child.readNext(id))
		return false;

	do
	{
		switch (id.tag) {
		case DW_TAG_subprogram:
			getSubprogramPCBounds(child, id, bounds, cu);
			break;
		case DW_TAG_namespace:
		case DW_TAG_module:
			/* FIXME: carlton/2004-01-16: Should we do this for
			DW_TAG_class_type/DW_TAG_structure_type, too?  I think
			that current GCC's always emit the DIEs corresponding
			to definitions of methods of classes as children of a
			DW_TAG_compile_unit or DW_TAG_namespace (as opposed to
			the DIEs giving the declarations, which could be
			anywhere).  But I don't see any reason why the
			standards says that they have to be there.  */
			pcRange_t current_bounds;
			if (getScopePCBounds(child, id, current_bounds, cu))
			{
				bounds.pclo = min(bounds.pclo, current_bounds.pclo);
				bounds.pchi = max(bounds.pchi, current_bounds.pchi);
			}
			break;
		default:
			/* Ignore.  */
			break;
		}

	} while (child.readSibling(id));

	return bounds.pclo != -1;
}

const DIECursor& getCompilationUnitCursor(unsigned long long off)
{
	cuDataMap_t::iterator it = cuCursorMap.find(off);
	if (it != cuCursorMap.end())
		return it->second;

	auto it2 = cuCursorMap.insert(std::make_pair(off, DIECursor((DWARF_CompilationUnit*)(dbgimg->debug_info + off))));
	assert(it2.second);
	DIECursor& result = it2.first->second;
	DWARF_InfoData id;
	while (result.readNext(id))
	{
		if (id.tag == DW_TAG_compile_unit)
		{
			result.cu.language = get_cu_language(id.language);
			result.cu.name = id.name;
			result.cu.dir = id.dir;
			result.cu.producer = id.producer;
			//result.cu.identifier_case = id.identifier_case;
			//result.cu.base_types = id.base_types;
			result.cu.stmt_list = id.stmt_list;
			//result.cu.macro_info = id.macro_info;
			result.cu.base_address = id.pcentry ? id.pcentry : id.pclo;
			result.cu.addr_base = id.addr_base;
			result.cu.ranges_base = id.ranges_base;

			pcRange_t bounds;
			getScopePCBounds(result, id, bounds, result.cu);
			if (bounds.pclo == -1)
				bounds.pclo = bounds.pchi;

			result.cu.pclo = bounds.pclo;
			result.cu.pchi = bounds.pchi;
			break;
		}
	}
	return result;
}

DIECursor findCompilationUnitChildCursor(byte* addrInside)
{
	const DIECursor* result = NULL;
	unsigned long long off = 0;
	if (!cuCursorMap.empty())
	{
		cuDataMap_t::iterator upper = cuCursorMap.upper_bound(addrInside - (byte*)dbgimg->debug_info);
		--upper;
		const DIECursor& cucursor = upper->second;
		const DWARF_CompilationUnit* header = cucursor.cu.header;
		if (header->isInBounds(addrInside))
			result = &cucursor;
		else
			off = upper->first + header->getLength();
	}
	if (!result)
	{
		while (off < dbgimg->debug_info_length)
		{
			const DIECursor& cucursor = getCompilationUnitCursor(off);
			const DWARF_CompilationUnit* header = cucursor.cu.header;
			if (header->isInBounds(addrInside))
			{
				result = &cucursor;
				break;
			}
			off += header->getLength();
		}
	}

	DIECursor temp = result ? *result : DIECursor::Invalid;
	if (result)
		temp.gotoSubtree(addrInside);
	return temp; // single return point to get NRVO kick in
}

CallSite* getCallSiteForPC(unsigned long long pc, bool insert)
{
	if (!insert)
	{
		callSiteMap_t::iterator it = callSiteMap.find(pc);
		if (it != callSiteMap.end())
			return &it->second;
		return NULL;
	}

	return &callSiteMap[pc];
}

const CallSite* findCallSiteForTarget(unsigned long long target)
{
	for (const auto& callsite : callSiteMap)
	{
		if (callsite.second.getTargetAddr() == target)
			return &callsite.second;
	}
	return NULL;
}

LOCCursor::LOCCursor(const CompilationUnitData& cu_, byte* section_beg, unsigned long section_len, unsigned long long off)
	: beg(section_beg)
	, end(section_beg + section_len)
	, ptr(beg + off)
	, cu(cu_)
	, last_base_entry(cu.header->addrSize() == 8 ? ULLONG_MAX : ULONG_MAX)
{
	default_address_size = cu.header->addrSize();
}

unsigned long long LOCCursor::baseAddress() const
{
	if (last_base_entry.isvalid())
		return last_base_entry.base_address; //+ img->secTextRelocOffset();
	return cu.base_address; //+ img->secTextRelocOffset();
}

bool LOCCursor::readNext(LOCEntry& entry)
{
	do {
		if (ptr >= end)
			return false;
		entry.beg_offset = RDsize(ptr, default_address_size);
		entry.end_offset = RDsize(ptr, default_address_size);
	} while (last_base_entry.convertFrom(entry));

	if (entry.eol())
		//TODO: gcc has some bugs which emits 0 for both offsets, but a valid entry with location expr.
		//This could also be the first entry. In this case it would be decoded as an empty location list.
		//We need to find a way to discover this bug and continue with decoding, if we realy want to use these.
		//see: https://sourceware.org/ml/binutils/2010-08/msg00386.html
		return false;

	entry.beg_offset += baseAddress();
	entry.end_offset += baseAddress();
	entry.attr.type = Block;
	entry.attr.block.len = RD2(ptr);
	entry.attr.block.ptr = ptr;
	ptr += entry.attr.expr.len;
	return true;
}

unsigned long long CallSite::getTargetAddr(const FrameInfoData* callerFrame) const
{
	switch (target_type)
	{
	case CallSite::dwarf_block:
		if (!callerFrame)
			return -1;
		Location loc = decodeLocation(target.block, cu, callerFrame, DW_AT_GNU_call_site_target, 0);
		if (loc.is_abs())
			return loc.off;
		return -1;
	case CallSite::physname:
		unsigned long off;
		int section;
		section = dbgimg->findSymbol(target.physname, off);
		if (section == -1)
			return -1;
		return off + dbgimg->getSectionVMA(section);
	case CallSite::physaddr:
		return target.physaddr;
	default:
		return -1;
	}
}

unsigned long long CallSite::getImportTargetAddr() const
{
	switch (target_type)
	{
	case CallSite::physname:
		unsigned long off;
		int section;
		section = img->findImportSymbol(target.physname, off);
		if (section == -1)
			return -1;
		return off + img->getSectionVMA(section);
	case CallSite::physaddr:
	case CallSite::dwarf_block:
	default:
		return -1;
	}
}