#include <string>
#include <algorithm>

struct SOpenedFileCtx
{
public:
    SOpenedFileCtx(HANDLE h, bool bChunked, const std::wstring FileNameFull, ULONGLONG ullBaseOfs): handle(h), FileName(FileNameFull), offset(ullBaseOfs), chunk(bChunked)
    {
        if (handle == INVALID_HANDLE_VALUE) {
            handle = 0;
        }
    }

    ~SOpenedFileCtx() 
    {
        Close();
    }

    void Close() {
        if (handle) {
            ::CloseHandle(handle);
            handle = NULL;
        }
    }

public:
    HANDLE handle;
    ULONGLONG offset;
    std::wstring FileName;
    bool chunk;
};

#define NEW_CONTEXT(handle, bChunked, sFileNameWithoutSuffix, ullBaseOfs) \
    (ULONG_PTR)(new SOpenedFileCtx(handle, bChunked, sFileNameWithoutSuffix, ullBaseOfs))
#define GET_CONTEXT(ctx) \
    ((SOpenedFileCtx*)((ULONG_PTR)(ctx)))

class CSplittingHelper
{
public:
    ULONGLONG MaxChunkSize;
    std::wstring m_sSuffix;
    unsigned int m_nSuffixDigits;

public:
    CSplittingHelper(): MaxChunkSize(1024LL * 1024 * 100), m_nSuffixDigits(4)
    {
        m_sSuffix = L".part";
    }

public:
    std::wstring MakeFileName(std::wstring sOriginalName, ULONGLONG nChunk) 
    {
        std::wstring sChunk = std::to_wstring(nChunk);
        if (sChunk.length() < m_nSuffixDigits) {
            std::wstring sZeros;
            sZeros.resize(m_nSuffixDigits - sChunk.length(), L'0');
            sChunk = sZeros + sChunk;
        }
        std::wstring sFileName = sOriginalName + m_sSuffix + sChunk;
        return sFileName;
    }

    bool HaveBigFileSuffix(LPCWSTR sName, __out std::wstring& sNameWithoutSuffix, __out ULONGLONG& nBaseOfs) 
    {
        sNameWithoutSuffix = sName;
        nBaseOfs = 0;
        std::wstring s = sNameWithoutSuffix;
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        auto nPos = s.rfind(m_sSuffix);
        if (nPos == s.npos) {
            return false;
        }
        auto nDPosStart = nPos + m_sSuffix.length();
        auto nDPos = nDPosStart;
        while (nDPos < s.length()) {
            auto c = s[nDPos];
            if (c >= L'0' && c <= L'9') ++nDPos;
            else break;
        }
        if (nDPos != s.length()) {
            return false;
        }
        sNameWithoutSuffix = sNameWithoutSuffix.substr(0, nPos);
        nBaseOfs = std::stoull(s.substr(nDPosStart)) * MaxChunkSize;
        return true;
    }

    void FileEnum_Helper(PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo,
        WIN32_FIND_DATAW& findData, int& count)
    {
        ULONGLONG ullFileSize = findData.nFileSizeLow | (((ULONGLONG)findData.nFileSizeHigh) << 32);
        if (ullFileSize < MaxChunkSize)
        {
            FillFindData(&findData, DokanFileInfo);
            count++;
        }
        else
        {
            WIN32_FIND_DATAW findDataC = findData;
            std::wstring sPrefix = findData.cFileName;
            ULONGLONG nChunks = (ullFileSize + MaxChunkSize - 1) / MaxChunkSize;
            for (ULONGLONG i = 0; i < nChunks; ++i) 
            {
                std::wstring sFileName = MakeFileName(sPrefix, i);
                wcscpy_s(findDataC.cFileName, _countof(findDataC.cFileName), sFileName.c_str());

                ULONGLONG ullCurChunkSize = MaxChunkSize;
                if (i * MaxChunkSize + ullCurChunkSize > ullFileSize) {
                    ullCurChunkSize = ullFileSize - i * MaxChunkSize;
                }
                findDataC.nFileSizeLow = (DWORD)ullCurChunkSize;
                findDataC.nFileSizeHigh = (DWORD)(ullCurChunkSize >> 32);

                FillFindData(&findDataC, DokanFileInfo);
                count++;
            }
        }
    }
};