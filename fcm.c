#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <locale.h>
#include <assert.h>
#include <windows.h>
#include <shlwapi.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* utils */

void readfile(const char *filename, u8 **buf, u32 *size) {
    assert(buf && size);
    FILE *fp = fopen(filename, "rb");
    assert(fp);
    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *buf = malloc(*size);
    assert(*buf);
    fread(*buf, 1, *size, fp);
    fclose(fp);
}

void writefile(const char *filename, const void *buf, u32 size) {
    FILE *fp = fopen(filename, "wb");
    assert(fp);
    fwrite(buf, 1, size, fp);
    fclose(fp);
}

/* crypt */

const u8 cryptkey[] = "/><~F*&2$..*()@#$_+:>?ZXs4Q";

#define cryptData(type,buf,size) do { \
    type *_p = (type*)(buf); \
    u32 _size = size; \
    for (u32 _i = 0; _i < _size; ++_i) *_p++ ^= cryptkey[_i % 27]; \
} while (0)

/* extract */

#define BOM L"\xFEFF"

typedef struct CMHead {
    u16 header[6];
    u32 size;
    float version;
    u16 CRLF[2];
    u16 data[];
} CMHead, CMF, CML;
// head data resource
// head 不加密
// data u16加密
// resource u8加密

// CME:
// CMF 135 再做一次u8加密
// CONF 134 u16加密
// CONF 144 CRC32+salt

// CME: CheatMaker Executable
// CMF: CheatMaker Modifier File
// CML: EmuList File
// CMC: Cheat File

u32 checkCMHeader(const u16 *data, u32 *version) {
    #define PACK(ty, skip) { *version = ty; return skip; }
    // BOM L"cm[flc](\r.|.{2}\r\n)"
    // BOM "cm[fl]."
    // BOM
    // ansi
    const u8 *p = (const u8 *)data;
    if (p[0] != 0xFF || p[1] != 0xFE) PACK(1, 0)
    if (data[1] == 'c' && data[2] == 'm' && (data[3] == 'f' || data[3] == 'l' || data[3] == 'c')) {
        if (data[4] == '\r') PACK(4, 12)
        if (data[6] == '\r' && data[7] == '\n') PACK(5, 16);
        PACK(6, 24); // new ver.
    }
    if (p[2] == 'c' && p[3] == 'm' && (p[4] == 'f' || p[4] == 'l')) PACK(3, 6)
    PACK(2, 2)
}

u16 *cryptFile(const u16 *src, u32 src_size, u32 data_size) {
    u32 head_ver;
    u32 skip = checkCMHeader(src, &head_ver);
    u32 size;
    if (head_ver <= 5) {
        size = src_size - skip;
    } else {
        CMHead *h = (CMHead *)src;
        size = h->size;
    }
    const u16 *data = (const u16 *)((u8 *)src + skip);
    if (data_size) size = data_size;
    u16 *buf;
    if (head_ver != 1) {
        u32 count = size / 2;
        buf = malloc((count + 1) * 2);
        buf[count] = 0;
        memcpy(buf, data, size);
        cryptData(u16, buf, count); // 从ver. 4开始，理论上支持动态密钥
    } else {
        int len = MultiByteToWideChar(0, 0, (LPCCH)data, -1, NULL, 0);
        buf = malloc(len * 2);
        MultiByteToWideChar(0, 0, (LPCCH)data, -1, buf, len);
    }
    return buf;
}

void checkCMFHeader(CMF *cmf) {
    assert(memcmp(cmf->header, BOM "cmf", 8) == 0);
}

u16 *cryptCMF(CMF *cmf) {
    checkCMFHeader(cmf);
    cryptData(u16, cmf->data, cmf->size / 2);
    return cmf->data;
}

void checkCMLHeader(CML *cml) {
    assert(memcmp(cml->header, BOM "cml", 8) == 0);
}

u16 *cryptCML(CML *cml) {
    checkCMLHeader(cml);
    cryptData(u16, cml->data, cml->size / 2);
    return cml->data;
}

u16 *cryptCML_CMC(CML *cml) {
    u32 version;
    checkCMHeader((u16 *)cml, &version);
    assert(version == 6);
    cryptData(u16, cml->data, cml->size / 2);
    return cml->data;
}

#define cryptCONF(buf,size) cryptData(u16, buf, size / 2)

#define cryptCMFInCME(buf, size) cryptData(u8, buf, size)

#define CMFName 135
#define CONFName 134
#define CRCName 144 // salt 0x1310FF78
#define RsrcLanguage MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED)

void readResource(HMODULE hModule, LPCWSTR lpType, WORD lpName, u8 **buf, size_t *size) {
    HRSRC hResInfo = FindResourceExW(hModule, lpType, MAKEINTRESOURCEW(lpName), RsrcLanguage);
    assert(hResInfo);
    HGLOBAL hResData = LoadResource(hModule, hResInfo);
    assert(hResData);
    LPVOID data = LockResource(hResData);
    assert(data);
    *size = SizeofResource(hModule, hResInfo);
    *buf = malloc(*size);
    assert(*buf);
    memcpy(*buf, data, *size);
}

void extractCMF(HMODULE hModule, const char *dir) {
    u8 *cmf; size_t size;
    readResource(hModule, L"CMF", CMFName, &cmf, &size);
    cryptCMFInCME(cmf, size);
    char buf[MAX_PATH];
    PathCombineA(buf, dir, "CMF.cmf");
    writefile(buf, cmf, size);
    free(cmf);
}

void extractCONF(HMODULE hModule, const char *dir) {
    u8 *conf; size_t size;
    readResource(hModule, L"CONF", CONFName, &conf, &size);
    cryptCONF(conf, size);
    char buf[MAX_PATH];
    PathCombineA(buf, dir, "CONF.txt");
    writefile(buf, conf, size);
    free(conf);
}

void extractCME(LPCWSTR filename, const char *dir) {
    HMODULE hMod = LoadLibraryExW(filename, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    assert(hMod);
    extractCMF(hMod, dir);
    extractCONF(hMod, dir);
    FreeLibrary(hMod);
}

#define findCMFPwd(buf) (wcsstr(buf, L"passWord=") + 9)

void extractCMFPwd(u16 *buf, CMF *cmf) {
    u16 *data = cryptCMF(cmf);
    u16 *pwd = findCMFPwd(data);
    u16 *p = buf;
    while (*pwd != '\r') *p++ = *pwd++;
    *p = 0;
}

void removeCMFPwd(CMF *cmf, u32 *size) {
    u16 *data = cryptCMF(cmf);
    u16 *pwd = findCMFPwd(data);
    u16 *p = pwd;
    while (*p != '\r') ++p;
    u32 pwd_len = (p - pwd) * 2;
    memmove(pwd, p, *size - ((u8*)p - (u8*)cmf));
    cmf->size -= pwd_len;
    *size -= pwd_len;
    cryptCMF(cmf);
}

CMF *readCMF(const char *filename, u32 *size) {
    u8 *buf;
    readfile(filename, &buf, size);
    return (CMF*)buf;
}

CML *readCML(const char *filename) {
    u8 *buf; u32 size;
    readfile(filename, &buf, &size);
    return (CML*)buf;
}

void showCMFPwd(const char *filename) {
    u16 pwd[256];
    u32 size;
    CMF *cmf = readCMF(filename, &size);
    extractCMFPwd(pwd, cmf);
    if (*pwd) {
        wprintf(L"Password: %s\n", pwd);
    } else {
        printf("This CMF has no password\n");
    }
    free(cmf);
}

static const char help_str[] =
"FCM (Fuck CheatMaker) - Made by Dangfer\n"
"Usage:\n"
"fcm e <CME> <dir> - extract CMF and CONF from CME\n"
"fcm p <CMF>       - extract password from CMF\n"
"fcm r <CMF>       - remove password from CMF\n" // not that meaningful
"fcm d <CML/CMC>   - decrypt CML/CMC\n\n"
"Share freely, learn openly. Never pay for repackaged community work.\n"
;

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");
    if (argc < 3) {
HELP:
        fputs(help_str, stderr);
        return 1;
    }
    switch (argv[1][0]) {
        case 'e': {
            if (argc < 4) goto HELP;
            u16 path[MAX_PATH];
            mbstowcs(path, argv[2], MAX_PATH);
            _putws(path);
            extractCME(path, argv[3]);
            break;
        }
        case 'p': {
            showCMFPwd(argv[2]);
            break;
        }
        case 'r': {
            u32 size;
            CMF *cmf = readCMF(argv[2], &size);
            removeCMFPwd(cmf, &size);
            writefile(argv[2], cmf, size);
            free(cmf);
            break;
        }
        case 'd': {
            CML *cml = readCML(argv[2]);
            u16 *data = cryptCML_CMC(cml);
            char path[MAX_PATH];
            sprintf(path, "%s.txt", argv[2]);
            writefile(path, data, cml->size);
            free(cml);
            break;
        }
        default: goto HELP;
    }
    return 0;
}
