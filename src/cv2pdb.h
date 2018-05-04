// Convert DMD CodeView debug information to PDB files
// Copyright (c) 2009-2010 by Rainer Schuetze, All Rights Reserved
//
// License for redistribution is given by the Artistic License 2.0
// see file LICENSE for further details

#ifndef __CV2PDB_H__
#define __CV2PDB_H__

#include "LastError.h"
#include "mspdb.h"
#include "readDwarf.h"

#include <windows.h>
#include <map>
#include <unordered_map>

extern "C" {
	#include "mscvpdb.h"
	#include "dcvinfo.h"
}

class PEImage;
struct DWARF_InfoData;
struct DWARF_CompilationUnit;

class CV2PDB : public LastError
{
public:
	CV2PDB(PEImage& image, const PEImage& debugimage);
	~CV2PDB();

	bool cleanup(bool commit);
	bool openPDB(const TCHAR* pdbname, const TCHAR* pdbref, bool readOnly = false);

	bool setError(const char* msg);
	bool createModules();

	bool initLibraries();
	const BYTE* getLibrary(int i);
	bool initSegMap();

	enum
	{
		kCmdAdd,
		kCmdCount,
		kCmdNestedTypes,
		kCmdOffsetFirstVirtualMethod,
		kCmdHasClassTypeEnum,
		kCmdCountBaseClasses
	};
	enum
	{
		kInheritSingle,
		kInheritMultiple,
		kInheritVirtual,
		kInheritGeneral,
	};
	int _doFields(int cmd, codeview_reftype* dfieldlist, const codeview_reftype* fieldlist, int arg);
	int addFields(codeview_reftype* dfieldlist, const codeview_reftype* fieldlist, int maxdlen);
	int countFields(const codeview_reftype* fieldlist);
	int countNestedTypes(const codeview_reftype* fieldlist, int type);

	int addAggregate(codeview_type* dtype, bool clss, bool iface, int n_element, int fieldlist, int property,
	                 int derived, int vshape, long long structlen, const char*name);
	int addClass(codeview_type* dtype, int n_element, int fieldlist, int property,
	                                   int derived, int vshape, long long structlen, const char*name);
	int addStruct(codeview_type* dtype, int n_element, int fieldlist, int property,
	                                    int derived, int vshape, long long structlen, const char*name);
	int addInterface(codeview_type * dtype, int n_element, int fieldlist, int property,
										int derived, int vshape, long long structlen, const char * name);
	int addUnion(codeview_type* dtype, int n_element, int fieldlist, int property,
	                                    long long unionlen, const char*name);
	int addEnum(codeview_type* dtype, int count, int fieldlist, int property,
	                                  int type, const char*name);

	int addPointerType(codeview_type* dtype, int type, int attr = CV_PTR_size(4) | CV_PTR_NEAR32, int inherit = 0, int baseseg = 0, int basetype = 0, const char* basename = 0);
	int addPointerType(unsigned char* dtype, int type, int attr = CV_PTR_size(4) | CV_PTR_NEAR32);
	int addModifierType(codeview_type* dtype, int type, int attr);

	int addFieldMember(codeview_fieldtype* dfieldtype, int attr, long long offset, int type, const char* name);
	int addFieldStaticMember(codeview_fieldtype* dfieldtype, int attr, int type, const char* name);
	int addFieldNestedType(codeview_fieldtype* dfieldtype, int type, const char* name);
	int addFieldBaseClass(codeview_fieldtype* dfieldtype, int attr, long long offset, int type);
	int addFieldSingleMethod(codeview_fieldtype * dfieldtype, int attr, int type, unsigned long vtoff, const char * name);
	int addFieldMethodList(codeview_fieldtype * dfieldtype, int count, int methodlist, const char * name);
	int addFieldEnumerate(codeview_fieldtype* dfieldtype, const char* name, long long val);
	int addFieldVFuncTable(codeview_fieldtype * dfieldtype, int type);
	int addMethodListMethod(codeview_mltype * dmltype, int attr, int type, unsigned long vtoff);

	void* safe_realloc(void* p, size_t size);
	void checkUserTypeAlloc(int size = 1000, int add = 10000);
	void checkGlobalTypeAlloc(int size, int add = 1000);
	void checkUdtSymbolAlloc(int size, int add = 10000);
	void checkModSymbolAlloc(int size, int add = 10000);
	void checkModFPODataAlloc(int size, int add = 10000);
	void checkModStringTableAlloc(int size, int add = 10000);
	void checkDWARFTypeAlloc(int size, int add = 10000);
	void writeUserTypeLen(codeview_type* type, int len);

	int getTypeModifier(int type, bool term_indir = false);
	const codeview_type* getTypeData(int type);
	const codeview_type* getUserTypeData(int type);
	const codeview_type* getGlobalTypeData(int type);
	const codeview_type* findCompleteClassType(const codeview_type* cvtype, int* ptype = 0);

	int findMemberFunctionType(codeview_symbol* lastGProcSym, int thisPtrType);
	int createEmptyFieldListType();
	int createEmptyArgListType();

	int fixProperty(int type, int prop, int fieldType);
	bool derivesFromObject(const codeview_type* cvtype);
	bool isCppInterface(const codeview_type* cvtype);
	bool isClassType(int type);

	int sizeofClassType(const codeview_type* cvtype);
	int sizeofBasicType(int type);
	int sizeofType(int type);

	// to be used when writing new type only to avoid double translation
	int translateType(int type);
	int getBaseClass(const codeview_type* cvtype);
	int countBaseClasses(const codeview_type* cvtype);

	bool nameOfBasicType(int type, char* name, int maxlen);
	bool nameOfType(int type, char* name, int maxlen);
	bool nameOfDynamicArray(int indexType, int elemType, char* name, int maxlen);
	bool nameOfAssocArray(int indexType, int elemType, char* name, int maxlen);
	bool nameOfDelegate(int thisType, int funcType, char* name, int maxlen);
	bool nameOfOEMType(codeview_oem_type* oem, char* name, int maxlen);
	bool nameOfModifierType(int type, int mod, char* name, int maxlen);

	int numeric_leaf(long long* value, const void* leaf);
	int copy_leaf(unsigned char* dp, int& dpos, const unsigned char* p, int& pos);

	const char* appendDynamicArray(int indexType, int elemType);
	const char* appendAssocArray(int keyType, int elemType);
	const char* appendDelegate(int thisType, int funcType);
	int  appendObjectType (int object_derived_type, int enumType, const char* classSymbol);
	int  appendPointerType(int pointedType, int attr);
	int  appendModifierType(int type, int attr);
	int  appendTypedef(int type, const char* name, int mode, bool saveTranslation = true);
	int  appendComplex(int cplxtype, int basetype, int elemsize, const char* name);
	void appendTypedefs();
	int  appendEnumerator(const char* typeName, const char* enumName, int enumValue, int prop);
	int  appendClassTypeEnum(const codeview_type* fieldlist, int type, const char* name);
	unsigned short appendStackVar(const char* name, int type, const Location& loc, const Location& cfa);
	unsigned short appendRegVar(const char* name, int type, const Location& loc, const Location& cfa);
	void appendLocalVar(const char* name, int type, bool isparam);
	void appendGlobalVar(const char* name, int type, int seg, int offset);
	unsigned short appendRangeStack(pcRange_t range, const std::vector<pcRange_t>& gaps, const Location& loc, const Location& cfa, bool fullscope = false);
	unsigned short appendRangeReg(pcRange_t range, const std::vector<pcRange_t>& gaps, const Location& loc, const Location& cfa);
	void appendRangeProg(pcRange_t range, const std::vector<pcRange_t>& gaps, int prog);
	void appendEndArg();
	void appendEnd(int offStart);
	int  appendLexicalBlock(const pcRange_t& range, int offParent);
	void appendLabel(const char* name, unsigned long long pc);
	int  appendThunk(const char* name, const pcRange_t& range);
	void appendFPOData(const PDB_FPO_DATA& fpo_data);
	int appendString(const char* str);

	bool hasClassTypeEnum(const codeview_type* fieldlist);
	bool insertClassTypeEnums();
	int  insertBaseClass(const codeview_type* fieldlist, int type);

	bool initGlobalTypes();
	bool initGlobalSymbols();

	bool addTypes();
	bool addSrcLines();
	bool addPublics();

	codeview_symbol* findUdtSymbol(int type);
	codeview_symbol* findUdtSymbol(const char* name);
	bool addUdtSymbol(int type, const char* name, bool global = true);
	void ensureUDT(int type, const codeview_type* cvtype);

	// returns new destSize
	int copySymbols(BYTE* srcSymbols, int srcSize, BYTE* destSymbols, int destSize);

	bool writeSymbols(mspdb::Mod* mod, DWORD* data, int databytes, bool addGlobals, DWORD symtype = DEBUG_S_SYMBOLS);
	bool addSymbols(mspdb::Mod* mod, BYTE* symbols, int cb, bool addGlobals);
	bool addSymbols(int iMod, BYTE* symbols, int cb, bool addGlobals);
	bool addSymbols();
	bool addFPOData(mspdb::Mod* mod);
	bool addStringTable(mspdb::Mod* mod);

	bool markSrcLineInBitmap(int segIndex, int adr);
	bool createSrcLineBitmap();
	int  getNextSrcLine(int seg, unsigned int off);

	bool writeImage(const TCHAR* opath);

	mspdb::Mod* globalMod();

	// DWARF
	bool createDWARFModules();
	bool addDWARFModule(int imod, const CompilationUnitData& cu, bool create, bool import = false);
	bool addDWARFSymbols();
	bool addDWARFTypes();
	bool addDWARFLines();
	bool addDWARFPublics();
	bool writeDWARFImage(const TCHAR* opath);

	bool addDWARFSectionContrib(mspdb::Mod* mod, unsigned long long pclo, unsigned long long pchi);
	bool addDWARFProc(mspdb::Mod* mod, DWARF_InfoData& id, const CompilationUnitData& cu, DIECursor cursor);
	bool addDWARFCallSite(DWARF_InfoData& callid, const CompilationUnitData& cu, DIECursor cursor, const FrameInfoData* frame = NULL);
	int  addDWARFStructure(DWARF_InfoData& id, const CompilationUnitData& cu, DIECursor cursor);
	int  addDWARFEnum(DWARF_InfoData& id, const CompilationUnitData& cu, DIECursor cursor);
	int  addDWARFArray(DWARF_InfoData& arrayid, DIECursor cursor);
	int  addDWARFBasicType(const char*name, int encoding, int byte_size);
	int  addDWARFVTShape(int count, int* vtablePtrType = NULL);
	int  addDWARFSubroutineType(DWARF_InfoData& id, const CompilationUnitData& cu, DIECursor cursor, int class_type = 0, bool inlined = false);
	int  getTypeByDWARFPtr(const CompilationUnitData& cu, byte* ptr, bool udt = false);
	const DWARF_InfoData* getThunkByImportOffset(unsigned long long off);
	long long  getDWARFTypeSize(byte* ptr);
	int  getDWARFTypeCVModifier(byte* typePtr, bool term_indir = false);
	int  getDWARFSubrangeType(DWARF_InfoData & id, const CompilationUnitData& cu);
	long long getDWARFSubrangeBounds(DWARF_InfoData & id, const CompilationUnitData& cu, long long& upperBound);
	long long getDWARFArrayBounds(DWARF_InfoData& arrayid, DIECursor cursor, long long& upperBound);
	long long getDWARFByteSize(DWARF_InfoData & id, const CompilationUnitData & cu);
	// returns true if there is a this param, false otherwise
	bool getDWARFSubroutineParameters(DWARF_InfoData & procid, const CompilationUnitData & cu, DIECursor cursor, std::vector<DWARF_Parameter>* params = NULL);
	std::vector<DWARF_StructMember> getDWARFStructMembers(byte * typePtr, long long off);
	std::vector<DWARF_StructMember> getDWARFStructMembers(DWARF_InfoData & structid, const char* structname, const CompilationUnitData & cu, DIECursor cursor, long long off);
	std::vector<CallSite*>* CV2PDB::getTailCallListByType(const CompilationUnitData& cu, byte* typePtr);

	bool mapTypes();
	bool createTypes();

// private:
	BYTE* libraries;

	PEImage& img;
	const PEImage& dbgimg; // for separated debug images

	mspdb::PDB* pdb;
	mspdb::DBI *dbi;
	mspdb::IPI *ipi; // ID pool interface
	mspdb::TPI *tpi;

	mspdb::Mod** modules;
	mspdb::Mod* globmod;
	int countEntries;

	OMFSignatureRSDS* rsds;

	OMFSegMap* segMap;
	OMFSegMapDesc* segMapDesc;
	int* segFrame2Index;

	OMFGlobalTypes* globalTypeHeader;

	unsigned char* globalTypes;
	int cbGlobalTypes;
	int allocGlobalTypes;

	unsigned char* userTypes;
	int* pointerTypes;
	int cbUserTypes;
	int allocUserTypes;

	unsigned char** modTypes;
	int* cbModTypes;

	unsigned char* globalSymbols;
	int cbGlobalSymbols;

	unsigned char* staticSymbols;
	int cbStaticSymbols;

	unsigned char* udtSymbols;
	int cbUdtSymbols;
	int allocUdtSymbols;

	unsigned char* modSymbols;
	int cbModSymbols;
	int allocModSymbols;

	unsigned char* modFPOData;
	int cbModFPOData;
	int allocModFPOData;

	unsigned char* modStringTable;
	int cbModStringTable;
	int allocModStringTable;

	unsigned char* dwarfTypes;
	int cbDwarfTypes;
	int allocDwarfTypes;

	int nextGlobalType;
	int nextUserType;
	int nextDwarfType;
	int objectType;

	int emptyFieldListType;
	int emptyArgListType;
	int classEnumType;
	int ifaceEnumType;
	int cppIfaceEnumType;
	int structEnumType;

	int classBaseType;
	int ifaceBaseType;
	int cppIfaceBaseType;
	int structBaseType;

	// D named types
	int typedefs[20];
	int translatedTypedefs[20];
	int cntTypedefs;

	bool addClassTypeEnum;
	bool addStringViewHelper;
	bool useGlobalMod;
	bool thisIsNotRef;
	bool v3;
	bool debug;
	const char* lastError;

	int srcLineSections;
	std::vector<bool>* srcLineStart; // array of bitmaps per segment, indicating whether src line start is available for corresponding address

	double Dversion;
	int vsversion;

	// DWARF
	long long codeSegOff;
	long codeSegOffRVA;
	std::unordered_map<byte*, int> mapOffsetToType;
	std::unordered_map<byte*, int> mapOffsetToUdtType;
	std::vector<int> nextDwarfTypeOfModule;
	std::unordered_map<byte*, std::vector<CallSite*>> mapOffsetToTailCallList;
	std::unordered_map<byte*, std::vector<DWARF_StructMember>> mapOffsetToStructMembers;
	std::unordered_map<unsigned long long, DWARF_InfoData> mapImportsToThunks;
	std::unordered_map<int, int> mapCountToVTShapeType;
};

#endif //__CV2PDB_H__
