use zerocopy::little_endian::{U16, U32};

pe_struct! {
    /// The IMAGE_FILE_HEADER (COFF header) of the NT headers.
    pub struct ImageFileHeader {
        machine: U16 => MachineType,
        number_of_sections: U16 => u16,
        time_date_stamp: U32 => u32,
        pointer_to_symbol_table: U32 => u32,
        number_of_symbols: U32 => u32,
        size_of_optional_header: U16 => u16,
        characteristics: U16 => FileCharacteristics,
    }
}

bitflags::bitflags! {
    /// Characteristics of the file header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileCharacteristics: u16 {
        const RELOCS_STRIPPED = 0x0001;
        const EXECUTABLE_IMAGE = 0x0002;
        const LINE_NUMS_STRIPPED = 0x0004;
        const LOCAL_SYMS_STRIPPED = 0x0008;
        /// The Windows name of this flag is misspelled (`IMAGE_FILE_AGGRESIVE_WS_TRIM`).
        const AGGRESSIVE_WS_TRIM = 0x0010;
        const LARGE_ADDRESS_AWARE = 0x0020;
        const BYTES_REVERSED_LO = 0x0080;
        const MACHINE_32BIT = 0x0100;
        const DEBUG_STRIPPED = 0x0200;
        const REMOVABLE_RUN_FROM_SWAP = 0x0400;
        const NET_RUN_FROM_SWAP = 0x0800;
        const SYSTEM = 0x1000;
        const DLL = 0x2000;
        const UP_SYSTEM_ONLY = 0x4000;
        const BYTES_REVERSED_HI = 0x8000;
    }
}

impl From<u16> for FileCharacteristics {
    fn from(bits: u16) -> Self {
        Self::from_bits_retain(bits)
    }
}

const AMD64: u16 = 0x8664;
const I386: u16 = 0x14c;

pe_enum! {
    /// Target machine of the file.
    pub enum MachineType: u16, other = "unknown" {
        Unknown = 0x0 => "unknown",
        TargetHost = 0x0001 => "Interacts with the host and not a WOW64 guest",
        I386 = I386 => "Intel 386",
        I860 = 0x14d => "Intel i860",
        R3000 = 0x162 => "MIPS R3000",
        R4000 = 0x166 => "MIPS little endian (R4000)",
        R10000 = 0x168 => "MIPS R10000",
        WceMipsV2 = 0x169 => "MIPS little endian WCI v2",
        OldAlpha = 0x183 => "old Alpha AXP",
        /// Also known as AXP.
        Alpha = 0x184 => "Alpha AXP",
        Sh3 = 0x1a2 => "Hitachi SH3",
        Sh3Dsp = 0x1a3 => "Hitachi SH3 DSP",
        Sh3E = 0x1a4 => "Hitachi SH3E",
        Sh4 = 0x1a6 => "Hitachi SH4",
        Sh5 = 0x1a8 => "Hitachi SH5",
        Arm = 0x1c0 => "ARM little endian",
        Thumb = 0x1c2 => "Thumb",
        ArmNt = 0x1c4 => "ARM Thumb-2 Little-Endian",
        Am33 = 0x1d3 => "Matsushita AM33",
        PowerPc = 0x1f0 => "PowerPC little endian",
        PowerPcFp = 0x1f1 => "PowerPC with floating point support",
        Ia64 = 0x200 => "Intel IA64",
        Mips16 = 0x266 => "MIPS16",
        M68K = 0x268 => "Motorola 68000 series",
        /// Also known as AXP64.
        Alpha64 = 0x284 => "Alpha AXP 64-bit",
        MipsFpu = 0x366 => "MIPS with FPU",
        MipsFpu16 = 0x466 => "MIPS16 with FPU",
        TriCore = 0x520 => "Tricore",
        Cef = 0xcef => "CEF",
        Ebc = 0xebc => "EFI Byte Code",
        RiscV32 = 0x5032 => "RISC-V 32-bit address space",
        RiscV64 = 0x5064 => "RISC-V 64-bit address space",
        RiscV128 = 0x5128 => "RISC-V 128-bit address space",
        LoongArch32 = 0x6232 => "LoongArch 32-bit processor family",
        LoongArch64 = 0x6264 => "LoongArch 64-bit processor family",
        Amd64 = AMD64 => "AMD64",
        M32R = 0x9041 => "Mitsubishi M32R little endian",
        Arm64 = 0xaa64 => "ARM64 Little-Endian",
        Cee = 0xc0ee => "clr pure MSIL",
        LinuxDotnet64 = AMD64 ^ 0x4644 => "Linux .NET x64",
        OsXDotnet64 = AMD64 ^ 0x7b79 => "Mac OS .NET x64",
        FreeBsdDotnet64 = AMD64 ^ 0xadc4 => "FreeBSD .NET x64",
        NetBsdDotnet64 = AMD64 ^ 0x1993 => "NetBSD .NET x64",
        SunDotnet64 = AMD64 ^ 0x1992 => "Sun .NET x64",
        LinuxDotnet32 = I386 ^ 0x4644 => "Linux .NET x86",
        OsXDotnet32 = I386 ^ 0x7b79 => "Mac OS .NET x86",
        FreeBsdDotnet32 = I386 ^ 0xadc4 => "FreeBSD .NET x86",
        NetBsdDotnet32 = I386 ^ 0x1993 => "NetBSD .NET x86",
        SunDotnet32 = I386 ^ 0x1992 => "Sun .NET x86",
    }
}
