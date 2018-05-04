#include <windows.h>
#include "utf8.h"

size_t UTF8ToUnicode(LPCSTR lpSrcStr, __out_ecount_opt(cchDest) LPWSTR lpDestStr, size_t cchDest)
{
	// Convert to WCS and return a temp buffer
	if (lpDestStr == NULL)
		return 0;

	cchDest = MultiByteToWideChar(
		CP_UTF8,
		0,
		lpSrcStr,
		-1,
		lpDestStr,
		(int)cchDest
	);

	return cchDest;
}
size_t UTF8ToUnicodeCch(LPCSTR lpSrcStr, size_t cchSrc, __out_ecount_opt(cchDest) LPWSTR lpDestStr, size_t cchDest)
{
	// Convert to WCS and return a temp buffer
	if (lpDestStr == NULL)
		return 0;

	cchDest = MultiByteToWideChar(
		CP_UTF8,
		0,
		lpSrcStr,
		(int)cchSrc,
		lpDestStr,
		(int)cchDest
	);

	return cchDest;
}
size_t UnicodeToUTF8(LPCWSTR lpSrcStr, __out_ecount_opt(cchDest) LPSTR lpDestStr, size_t cchDest)
{
	// Convert to MBCS and return a temp buffer
	if (!lpDestStr)
		return 0;

	cchDest = WideCharToMultiByte(
		CP_UTF8,
		0,
		lpSrcStr,
		-1,
		lpDestStr,
		(int)cchDest,
		NULL,
		NULL);

	return cchDest;
}
size_t UnicodeToUTF8Cch(LPCWSTR lpSrcStr, size_t cchSrc, __out_ecount_opt(cchDest) LPSTR lpDestStr, size_t cchDest)
{
	// Convert to MBCS and return a temp buffer
	if (!lpDestStr)
		return 0;

	cchDest = WideCharToMultiByte(
		CP_UTF8,
		0,
		lpSrcStr,
		(int)cchSrc,
		lpDestStr,
		(int)cchDest,
		NULL,
		NULL);

	return cchDest;
}
size_t UnicodeLengthOfUTF8(PCSTR pUTF8)
{
	return MultiByteToWideChar(
		CP_UTF8,
		0,
		pUTF8,
		-1,
		NULL,
		0
	);
}
size_t UTF8LengthOfUnicode(PCWSTR pUni)
{
	return WideCharToMultiByte(
		CP_UTF8,
		0,
		pUni,
		-1,
		NULL,
		0,
		NULL,
		NULL);
}
size_t UnicodeLengthOfUTF8Cb(PCSTR pUTF8, size_t cbUTF)
{
	return MultiByteToWideChar(
		CP_UTF8,
		0,
		pUTF8,
		cbUTF,
		NULL,
		0
	);
}
size_t UTF8LengthOfUnicodeCch(PCWSTR pUni, size_t cchUni)
{
	return WideCharToMultiByte(
		CP_UTF8,
		0,
		pUni,
		cchUni,
		NULL,
		0,
		NULL,
		NULL);
}
