// Expands the WoW 3.3.5a (build 12340) character-creation data structures from
// 32 to 64 race IDs. All addresses in this file are specific to that client build.
//
// The patch adds two PE sections:
//   .wxlr64 - writable tables used by the original character-creation code
//   .wxlc64 - a small executable thunk for extended race validation
//
// Original module: https://github.com/Furioz420/

#include "patcher/PatchScript.hpp"

#include <cstdint>
#include <cstring>
#include <vector>
#include <windows.h>

namespace
{
    using namespace wxl::patcher;

    // PE section names are limited to eight bytes, including these terminators.
    constexpr char kDataSectionName[] = ".wxlr64";
    constexpr char kCodeSectionName[] = ".wxlc64";

    // PE section addresses and file positions must respect the alignments stored
    // in the executable's optional header.
    constexpr uint32_t AlignUp(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

    // Locate the 32-bit NT headers inside the in-memory executable image.
    IMAGE_NT_HEADERS32* Nt(std::vector<uint8_t>& bytes)
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
        return reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    }

    // Copy bytes from a preferred virtual address in the original executable.
    bool ReadVa(PeImage& pe, uint32_t va, void* dst, uint32_t len)
    {
        const uint32_t off = pe.VaToOffset(va);
        const auto& bytes = pe.bytes();
        if (off == 0 || static_cast<size_t>(off) + len > bytes.size()) return false;
        std::memcpy(dst, bytes.data() + off, len);
        return true;
    }

    // Write one little-endian 32-bit value at a preferred virtual address.
    bool WriteU32Va(PeImage& pe, uint32_t va, uint32_t value)
    {
        return pe.WriteVa(va, &value, sizeof(value));
    }

    // Some legacy patches are documented as raw file offsets rather than VAs.
    bool WriteU8Offset(PeImage& pe, uint32_t offset, uint8_t value)
    {
        auto& bytes = pe.bytes();
        if (offset >= bytes.size()) return false;
        bytes[offset] = value;
        return true;
    }

    /**
     * Append a new section to the PE without moving any existing section.
     *
     * The caller supplies the initial section contents and Windows section
     * characteristics. outVa receives the preferred virtual address at which
     * the Windows loader will map the section.
     */
    bool AppendSection(PeImage& pe, const char* sectionName, const std::vector<uint8_t>& data,
                       uint32_t characteristics, uint32_t& outVa)
    {
        if (!pe.valid() || pe.HasSection(sectionName) || data.empty()) return false;

        auto& bytes = pe.bytes();
        IMAGE_NT_HEADERS32* nt = Nt(bytes);
        auto& fh = nt->FileHeader;
        auto& oh = nt->OptionalHeader;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

        IMAGE_SECTION_HEADER& last = sec[fh.NumberOfSections - 1];
        const uint32_t imageBase = oh.ImageBase;
        const uint32_t sectionAlignment = oh.SectionAlignment;
        const uint32_t fileAlignment = oh.FileAlignment;
        const uint32_t secRva = AlignUp(last.VirtualAddress + last.Misc.VirtualSize, sectionAlignment);
        const uint32_t secRaw = AlignUp(static_cast<uint32_t>(bytes.size()), fileAlignment);
        const uint32_t rawSize = AlignUp(static_cast<uint32_t>(data.size()), fileAlignment);

        // A new section header must fit in the padding already reserved for PE
        // headers. Growing SizeOfHeaders would move every raw section instead.
        IMAGE_SECTION_HEADER* add = &sec[fh.NumberOfSections];
        if (reinterpret_cast<uint8_t*>(add + 1) - bytes.data() > static_cast<ptrdiff_t>(oh.SizeOfHeaders))
            return false;

        std::memset(add, 0, sizeof(*add));
        std::memcpy(add->Name, sectionName, strnlen(sectionName, 8));
        add->Misc.VirtualSize = static_cast<uint32_t>(data.size());
        add->VirtualAddress = secRva;
        add->SizeOfRawData = rawSize;
        add->PointerToRawData = secRaw;
        add->Characteristics = characteristics;

        oh.SizeOfImage = AlignUp(secRva + static_cast<uint32_t>(data.size()), sectionAlignment);
        fh.NumberOfSections += 1;

        // Materialize the aligned raw section at the end of the file.
        bytes.resize(secRaw + rawSize, 0);
        std::memcpy(bytes.data() + secRaw, data.data(), data.size());

        outVa = imageBase + secRva;
        return true;
    }

    class MoreRaces final : public PatchScript
    {
    public:
        const char* name() const override { return "more-races"; }

        bool Apply(PeImage& pe) const override
        {
            // A complete prior application is a successful no-op. Finding only
            // one section indicates a malformed or partially patched image.
            const bool hasDataSection = pe.HasSection(kDataSectionName);
            const bool hasCodeSection = pe.HasSection(kCodeSectionName);
            if (hasDataSection && hasCodeSection) return true;
            if (hasDataSection || hasCodeSection) return false;

            // Build-12340 patch sites. Addresses ending inside an instruction
            // identify the immediate operand that must be replaced, not the
            // beginning of that instruction.
            constexpr uint32_t kOriginalRaceNameTableVa = 0xB24180;       // stock name pointers
            constexpr uint32_t kRaceNamePatchVa = 0x4CDA43;              // name-table operand
            constexpr uint32_t kMemoryTableClearSizePatchVa = 0x4E1C34;  // memset length operand
            constexpr uint32_t kMemoryTableCleanupCountPatchVa = 0x4E1E9B; // cleanup loop count
            constexpr uint32_t kRaceRestrictionExtendedBranchVa = 0x4DFAF0; // JA instruction
            constexpr uint32_t kRaceRestrictionErrorVa = 0x4DFC32;       // stock Lua error path
            constexpr uint32_t kRaceRestrictionResultVa = 0x4DFC18;      // common Lua result path

            // This byte controls the number of characters accepted from
            // SMSG_CHAR_ENUM. It is unrelated to the maximum race ID.
            constexpr uint32_t kCharacterLimitOffset = 0x6404F;
            constexpr uint8_t kCharacterLimit = 0x1F;

            // Race IDs occupy one byte in the relevant client structures. This
            // module intentionally supports the closed range 0..63.
            constexpr uint32_t kRaceCount = 64;
            constexpr uint32_t kSexCount = 2;
            constexpr uint32_t kOriginalRaceCount = 12; // table entries 0..11
            constexpr uint32_t kFirstExtendedRace = 22; // IDs 12..21 remain reserved

            // Each address is the four-byte operand of an instruction that
            // references the stock [race ID][sex] character-creation cache.
            constexpr uint32_t kMemoryTablePatchVas[] = {
                0x4E157D, 0x4E16A3, 0x4E15B5, 0x4E20EE,
                0x4E222A, 0x4E2127, 0x4E1E94, 0x4E1C3A
            };

            // Layout of .wxlr64:
            //
            //   +0x000  128 cache pointers (64 races * 2 sexes)  [0x200 bytes]
            //   +0x200   64 race-name pointers                    [0x100 bytes]
            //   +0x300    1 zero DWORD used as an empty C string [0x004 bytes]
            constexpr uint32_t kMemoryTableOffset = 0;
            constexpr uint32_t kMemoryTableEntryCount = kRaceCount * kSexCount;
            constexpr uint32_t kMemoryTableSize = kMemoryTableEntryCount * sizeof(uint32_t);
            constexpr uint32_t kRaceNameTableOffset = kMemoryTableOffset + kMemoryTableSize;
            constexpr uint32_t kRaceNameTableSize = kRaceCount * sizeof(uint32_t);
            constexpr uint32_t kDummyOffset = kRaceNameTableOffset + kRaceNameTableSize;
            constexpr uint32_t kBlobSize = kDummyOffset + sizeof(uint32_t);

            // Start with a zero-filled cache and name table, then preserve the
            // stock names for IDs 0..11.
            std::vector<uint8_t> blob(kBlobSize, 0);
            if (!ReadVa(pe, kOriginalRaceNameTableVa, blob.data() + kRaceNameTableOffset,
                        kOriginalRaceCount * sizeof(uint32_t)))
                return false;

            // The cache is mutated while the character-creation UI is active,
            // so the data section must remain writable at runtime.
            uint32_t dataVa = 0;
            if (!AppendSection(pe, kDataSectionName, blob,
                               IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                               dataVa))
                return false;

            // IsRaceClassRestricted has a stock jump table for races 1..11. Route its
            // out-of-range branch through a small executable thunk: IDs 12..63 are
            // treated as unrestricted, while 0 and IDs above 63 keep the stock error.
            std::vector<uint8_t> restrictionThunk = {
                0x83, 0xFF, 0x0C,                         // cmp edi, 12
                0x0F, 0x82, 0, 0, 0, 0,                  // jb  stock error
                0x83, 0xFF, 0x3F,                         // cmp edi, 63
                0x0F, 0x87, 0, 0, 0, 0,                  // ja  stock error
                0xD9, 0xEE,                               // fldz
                0xE9, 0, 0, 0, 0                         // jmp common Lua-result path
            };
            uint32_t codeVa = 0;
            if (!AppendSection(pe, kCodeSectionName, restrictionThunk,
                               IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                               codeVa))
                return false;

            // x86 relative branches store target - address_after_instruction.
            // 9, 18 and 25 are the end offsets of the three branch instructions
            // in restrictionThunk above.
            const uint32_t errorFromLowerBound = kRaceRestrictionErrorVa - (codeVa + 9);
            const uint32_t errorFromUpperBound = kRaceRestrictionErrorVa - (codeVa + 18);
            const uint32_t resultFromThunk = kRaceRestrictionResultVa - (codeVa + 25);
            if (!WriteU32Va(pe, codeVa + 5, errorFromLowerBound)) return false;
            if (!WriteU32Va(pe, codeVa + 14, errorFromUpperBound)) return false;
            if (!WriteU32Va(pe, codeVa + 21, resultFromThunk)) return false;

            // Replace the stock "JA unsupported-race" destination with the
            // thunk while preserving the original six-byte JA instruction.
            uint8_t extendedRaceBranch[] = { 0x0F, 0x87, 0, 0, 0, 0 };
            const uint32_t branchDisplacement =
                codeVa - (kRaceRestrictionExtendedBranchVa + sizeof(extendedRaceBranch));
            std::memcpy(extendedRaceBranch + 2, &branchDisplacement, sizeof(branchDisplacement));
            if (!pe.WriteVa(kRaceRestrictionExtendedBranchVa, extendedRaceBranch,
                            sizeof(extendedRaceBranch)))
                return false;

            // Resolve the three objects inside the newly mapped data section.
            const uint32_t memoryTableVa = dataVa + kMemoryTableOffset;
            const uint32_t raceNameTableVa = dataVa + kRaceNameTableOffset;
            const uint32_t dummyVa = dataVa + kDummyOffset;

            // Unknown extended names point to a valid empty string instead of
            // nullptr, because the client forwards them to printf-style code.
            for (uint32_t i = kFirstExtendedRace; i < kRaceCount; ++i)
                if (!WriteU32Va(pe, raceNameTableVa + i * sizeof(uint32_t), dummyVa)) return false;

            // Redirect every cache access, then expand the corresponding clear
            // and destruction loops to cover all 64 race rows.
            for (const uint32_t patchVa : kMemoryTablePatchVas)
                if (!WriteU32Va(pe, patchVa, memoryTableVa)) return false;

            if (!WriteU32Va(pe, kMemoryTableClearSizePatchVa, kMemoryTableSize)) return false;
            if (!WriteU32Va(pe, kMemoryTableCleanupCountPatchVa, kRaceCount)) return false;
            if (!WriteU32Va(pe, kRaceNamePatchVa, raceNameTableVa)) return false;
            if (!WriteU8Offset(pe, kCharacterLimitOffset, kCharacterLimit)) return false;

            return true;
        }
    };

    const MoreRaces g_moreRaces;
}
