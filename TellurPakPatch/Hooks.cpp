#include "pch.h"
#include "Hooks.h"
#include "Patchfinder.h"
#include "Options.h"

bool InitializeForModule(uint64_t Module, void* Hook, void** OG, bool EOS)
{
    Tellurium::PE::ImageBase = Module;

    auto processRequestStr = Tellurium::Patchfinder::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest");

    if (!processRequestStr)
        processRequestStr = Tellurium::Patchfinder::FindStringRef(L"%p: request (easy handle:%p) has been added to threaded queue for processing");

    if (!processRequestStr)
        processRequestStr = Tellurium::Patchfinder::FindStringRef("STAT_FCurlHttpRequest_ProcessRequest");

    if (!processRequestStr)
        return false;

    uint64_t ProcessRequest = 0;
    for (int i = 0; i < 2048; i++)
    {
        if (EOS)
        {
            if (Tellurium::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
        }
        else
        {
            if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Tellurium::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Tellurium::Patchfinder::CheckBytes<0x48, 0x81, 0xEC>(processRequestStr, i, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x83, 0xEC>(processRequestStr, i, true))
            {
                for (int x = 0; x < 50; x++)
                {
                    if (Tellurium::Patchfinder::CheckBytes<0x40>(processRequestStr, i + x, true))
                    {
                        ProcessRequest = processRequestStr - i - x;
                        goto _found;
                    }
                    else if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i + x, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i + x, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i + x, true))
                        break;
                }
            }
        }
    }

    if (!ProcessRequest)
        return false;
_found:
    auto rdataSection = Tellurium::PE::GetSection(".rdata");
    const auto rdataStart = (uint8_t*)(Tellurium::PE::ImageBase + rdataSection->VirtualAddress);
    const auto rdataEnd = rdataStart + rdataSection->Misc.VirtualSize;

    uint64_t ProcessRequestVFT = 0;
    __m128i t = _mm_set1_epi32((int)(ProcessRequest & 0xffffffff));
    for (uint32_t i = 0; i < rdataSection->Misc.VirtualSize - (rdataSection->Misc.VirtualSize % 16); i += 16)
    {
        auto bytes = _mm_load_si128((const __m128i*)(rdataStart + i));
        int offset = _mm_movemask_epi8(_mm_cmpeq_epi32(bytes, t));

        if (offset == 0)
            continue;

        for (int q = 0; q < 16; q += 4)
        {
            int c = offset & (1 << q);
            if (c)
            {
                auto VFT = (uint64_t*)(rdataStart + i + q);

                if (*VFT == ProcessRequest)
                {
                    ProcessRequestVFT = uint64_t(VFT);
                    goto _foundVFT;
                }
            }
        }
    }

    if (!ProcessRequest)
        return false;

_foundVFT:
    DWORD oldProt;
    VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);

    if (OG)
        *OG = (void*)ProcessRequest;

    *(void**)ProcessRequestVFT = Hook;

    VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), oldProt, &oldProt);

    return true;
}

#include "LargePakPatch.h"

bool ProcessRequestHook(Tellurium::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(false);
    Tellurium::LargePakPatch::InitOnce();
    return Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG(_this);
}

bool ProcessRequest__EOS(Tellurium::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(true);
    Tellurium::LargePakPatch::InitOnce();
    return Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS(_this);
}

bool bInit = false;
void Tellurium::Hooks::Init()
{
    const auto gameModule = Tellurium::PE::ImageBase;


    if (Console)
    {
        AllocConsole();

        FILE* fptr;
        freopen_s(&fptr, "CONOUT$", "w+", stdout);
        SetConsoleTitleA("Tellurium (https://github.com/plooshi/Tellurium)");
    }

    constexpr static auto ReallocSig = Tellurium::Patchfinder::Pattern<"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?">();
    while (!Tellurium::Unreal::FMemory__Realloc)
        Tellurium::Unreal::FMemory__Realloc = ReallocSig.Scan();

    if (UseBackendParam)
    {
        Tellurium::Unreal::FString cmd = GetCommandLineW();
        auto pos = cmd.find(L"-backend=");
        if (pos != Tellurium::Unreal::FString::npos)
        {
            auto start = pos + 9;
            size_t end = start;
            while (end < cmd.Length - 1 && cmd.String[end] != L' ' && cmd.String[end] != L'\t' && cmd.String[end] != L'"')
                end++;
            while (end > start && (cmd.String[end - 1] == L'/' || cmd.String[end - 1] == L'\\' || cmd.String[end - 1] == L'"'))
                end--;
            Tellurium::Unreal::backend = cmd.substr(start, end - start);
        }
        else
            Tellurium::Unreal::backend = Backend;
    }

    while (!InitializeForModule(Tellurium::PE::ImageBase, ProcessRequestHook, (void**)&Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG, false));

    auto EOSBuf = LoadLibraryA("EOSSDK-Win64-Shipping");
    if (EOSBuf)
    {
        InitializeForModule(uint64_t(EOSBuf), ProcessRequest__EOS, (void**)&Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS, true);
    }

    Tellurium::PE::ImageBase = gameModule;
    bInit = true;
}

