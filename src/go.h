// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef __GO_H
#define __GO_H
#ifdef __cplusplus
extern "C" {
#endif

enum {
	goObjKindBool = 1,
	goObjKindInt,
	goObjKindInt8,
	goObjKindInt16,
	goObjKindInt32,
	goObjKindInt64,
	goObjKindUint,
	goObjKindUint8,
	goObjKindUint16,
	goObjKindUint32,
	goObjKindUint64,
	goObjKindUintptr,
	goObjKindFloat32,
	goObjKindFloat64,
	goObjKindComplex64,
	goObjKindComplex128,
	goObjKindArray,
	goObjKindChan,
	goObjKindFunc,
	goObjKindInterface,
	goObjKindMap,
	goObjKindPtr,
	goObjKindSlice,
	goObjKindString,
	goObjKindStruct,
	goObjKindUnsafePointer,
	goObjKindDirectIface = 1 << 5,
	goObjKindGCProg = 1 << 6,
	goObjKindNoPointers = 1 << 7,
	goObjKindMask = (1 << 5) - 1,
};

#ifdef __cplusplus
}
#endif
#endif /* __GO_H */
