#include "pch.h"
#include "LargePakPatch.h"
#include "Patchfinder.h"

namespace
{
    uint64_t ResolveRelativeCall(uint64_t instruction)
    {
        const auto displacement = *reinterpret_cast<int32_t*>(instruction + 1);
        return instruction + 5 + displacement;
    }

    bool PatchBytes(uint64_t address, const uint8_t* bytes, size_t size)
    {
        if (!address)
            return false;

        DWORD oldProtection;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtection))
            return false;

        memcpy(reinterpret_cast<void*>(address), bytes, size);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
        VirtualProtect(reinterpret_cast<void*>(address), size, oldProtection, &oldProtection);
        return true;
    }

    bool ReturnImmediately(uint64_t address)
    {
        constexpr uint8_t bytes[] = { 0xC3 };
        return PatchBytes(address, bytes, sizeof(bytes));
    }

    bool ReturnZero(uint64_t address)
    {
        constexpr uint8_t bytes[] = { 0x31, 0xC0, 0xC3 };
        return PatchBytes(address, bytes, sizeof(bytes));
    }

    uint64_t FindRequestExit()
    {
        const auto stringReference = Tellurium::Patchfinder::FindStringRef(L"Memory pools allocations failed, exiting...\n");
        if (!stringReference)
            return 0;

        int callCount = 0;
        for (int offset = 0; offset < 2048; ++offset)
        {
            const auto instruction = stringReference + offset;
            if (*reinterpret_cast<uint8_t*>(instruction) == 0xE8)
            {
                if (++callCount == 2)
                    return ResolveRelativeCall(instruction);
            }
        }

        return 0;
    }

    uint64_t FindUnsafeEnvironment()
    {
        const auto stringReference = Tellurium::Patchfinder::FindStringRef(L"UnsafeEnvironment_Title");
        if (!stringReference)
            return 0;

        for (int offset = 0; offset < 2048; ++offset)
        {
            const auto address = stringReference - offset;
            if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(address, 0, false) ||
                Tellurium::Patchfinder::CheckBytes<0x40, 0x55>(address, 0, false))
                return address;
        }

        return 0;
    }
}

bool Tellurium::LargePakPatch::Init()
{
    bool bIsModernFortnite = false;
    if (GetFileAttributesA("EOSSDK-Win64-Shipping.dll") != INVALID_FILE_ATTRIBUTES ||
        GetModuleHandleA("EOSSDK-Win64-Shipping") != NULL)
    {
        bIsModernFortnite = true;
    }

    if (bIsModernFortnite)
    {
        constexpr static auto RequestExitWithStatus1 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?">();
        constexpr static auto RequestExitWithStatus2 = Tellurium::Patchfinder::Pattern<"48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30">();
        constexpr static auto RequestExitWithStatus3 = Tellurium::Patchfinder::Pattern<"4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B">();

        auto RequestExitWithStatus = RequestExitWithStatus1.Scan();
        if (!RequestExitWithStatus) RequestExitWithStatus = RequestExitWithStatus2.Scan();
        if (!RequestExitWithStatus) RequestExitWithStatus = RequestExitWithStatus3.Scan();
        if (RequestExitWithStatus) ReturnImmediately(RequestExitWithStatus);

        constexpr static auto ShowAppSec1 = Tellurium::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8">();
        constexpr static auto ShowAppSec2 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 41 0F B6 D8 48 89 55 ? 88 5C 24 ?">();
        constexpr static auto ShowAppSec3 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1">();
        constexpr static auto ShowAppSec4 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?">();
        constexpr static auto ShowAppSec5 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8">();
        constexpr static auto ShowAppSec6 = Tellurium::Patchfinder::Pattern<"40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?">();
        constexpr static auto ShowAppSec7 = Tellurium::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?">();

        auto ShowAppSec = ShowAppSec1.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec2.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec3.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec4.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec5.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec6.Scan();
        if (!ShowAppSec) ShowAppSec = ShowAppSec7.Scan();
        if (ShowAppSec) ReturnImmediately(ShowAppSec);
    }
    else
    {
        // =========================================================================
        // CLASICO FORTNITE (v12.41)
        // Código exacto y comprobado de LargePakPatchRedirect para 12.41
        // =========================================================================
        const auto requestExit = FindRequestExit();
        const auto unsafeEnvironment = FindUnsafeEnvironment();

        constexpr static auto unsafeEnvironmentAltPattern = Tellurium::Patchfinder::Pattern<
            "E8 ? ? ? ? 48 8B 4D ? 48 85 C9 74 ? E8 ? ? ? ? 48 8B 4D ? 48 85 C9 74 ? E8 ? ? ? ? 4C 8B 7C 24 ? 4C 8B B4 24">();
        const auto unsafeEnvironmentAltCall = unsafeEnvironmentAltPattern.Scan();
        const auto unsafeEnvironmentAlt = unsafeEnvironmentAltCall
            ? ResolveRelativeCall(unsafeEnvironmentAltCall)
            : 0;

        ReturnImmediately(requestExit);
        if (unsafeEnvironment)
            ReturnZero(unsafeEnvironment);
        else if (unsafeEnvironmentAlt)
            ReturnImmediately(unsafeEnvironmentAlt);
    }

    return true;
}

bool Tellurium::LargePakPatch::InitOnce()
{
    static volatile LONG initialized = 0;
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0)
        return Init();

    return true;
}
