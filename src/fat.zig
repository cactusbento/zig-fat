//! https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
const std = @import("std");

pub const ReservedRegion = struct {
    bpb_common: BPB_common,
    bpb_extended: ExtentUnion,

    pub const ExtentUnion = union(enum) {
        fat1216: BPB_Extended_1216,
        fat32: BPB_Extended_32,
    };

    pub fn read(file: std.fs.File) !ReservedRegion {
        var common = try BPB_common.read(file, 0);
        var extended: ExtentUnion = undefined;
        if (common.RootEntCnt != 0) {
            extended = .{ .fat1216 = try BPB_Extended_1216.read(file, 36) };
        } else {
            extended = .{ .fat32 = try BPB_Extended_32.read(file, 36) };
        }

        return .{
            .bpb_common = common,
            .bpb_extended = extended,
        };
    }
};

test "ReservedRegion16" {
    var fat16 = try std.fs.cwd().openFile("testFat16.fs", .{});
    defer fat16.close();

    const rr = try ReservedRegion.read(fat16);
    std.debug.print("\n{any}\n{any}\n", .{ rr.bpb_common, rr.bpb_extended });
}
test "ReservedRegion32" {
    var fat32 = try std.fs.cwd().openFile("testFat32.fs", .{});
    defer fat32.close();

    const rr = try ReservedRegion.read(fat32);
    std.debug.print("\n{any}\n{any}\n", .{ rr.bpb_common, rr.bpb_extended });
}

/// Bios Parameter Block common to F12, F16 and F32.
pub const BPB_common = struct {
    /// 0xEB__90 <- More Common
    /// 0xE9____
    jmpBoot: u24,
    OEMName: [8]u8,
    /// 512, 1024, 2048, or 4096
    BytsPerSec: u16,
    /// 1, 2, 4, 8, 16, 32, 128
    SecPerClus: u8,
    /// Cannot be 0
    RsvdSecCnt: u16,
    /// 2 is recommended.
    NumFats: u8,
    /// For F12 and F16.
    /// Number of 32 Byte dir entries in root.
    RootEntCnt: u16,
    /// For F12 and F16.
    /// If 0, then BMB_TotSec32 must be non-0.
    TotSec16: u16 = 0,
    /// Legal Values: 0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    /// 0xF8 is standard for fixed (non-removable) media.
    /// 0xF0 is frequently used for removable media.
    Media: u8,
    /// For F12 and F16.
    /// Count of sectors occupied by one FAT.
    FATSz16: u16,
    /// Sectors per track for interrupt 0x13.
    SecPerTrk: u16 = 0,
    /// Number of heads for interrupt 0x13.
    NumHeads: u16 = 0,
    /// Only relevent for interrupt 0x13.
    /// Count of hidden sectors preceding this FAT volume.
    HiddSec: u32 = 0,
    /// For F32.
    /// If 0, then BMB_TotSec16 must be non-0.
    TotSec32: u32 = 0,

    pub fn read(file: std.fs.File, offset: u64) !BPB_common {
        var ret: BPB_common = undefined;

        try file.seekTo(offset);

        const self_ti: std.builtin.Type.Struct = @typeInfo(BPB_common).Struct;

        var curr_offset: usize = 0;
        inline for (self_ti.fields) |field| {
            const f: std.builtin.Type.StructField = field;
            try file.seekTo(offset + curr_offset);

            switch (@typeInfo(f.type)) {
                .Int => |I| {
                    const size: usize = I.bits / 8;
                    var buf: [size]u8 = undefined;
                    if (try file.read(&buf) != size) return error.EndOfFile;

                    const number: f.type = std.mem.readIntSlice(f.type, &buf, .Little);
                    @field(ret, f.name) = number;
                    curr_offset += size;
                },
                .Array => |arr| {
                    var buf: [arr.len]u8 = undefined;
                    if (try file.read(&buf) != arr.len) return error.EndOfFile;

                    @memcpy(&@field(ret, f.name), &buf);
                    curr_offset += arr.len;
                },
                else => unreachable,
            }
        }

        return ret;
    }
};

test "bpbc" {
    var fat16 = try std.fs.cwd().openFile("testFat16.fs", .{});
    defer fat16.close();

    var fat32 = try std.fs.cwd().openFile("testFat32.fs", .{});
    defer fat32.close();

    const bpbc16 = try BPB_common.read(fat16, 0);
    const bpbc32 = try BPB_common.read(fat32, 0);

    std.debug.print("\n{}\n{}\n", .{ bpbc16, bpbc32 });
}

/// Extend BPB for FAT12 and FAT16
pub const BPB_Extended_1216 = struct {
    /// Only relevent for interrupt 0x13.
    /// 0x80 or 0x00
    DrvNum: u8,
    /// Set to 0.
    Reserved: u8,
    /// Set to 0x29 if VolID or VolLab are present.
    BootSig: u8,
    /// Volumne Serial Number
    VolID: u32,
    /// Volume Label.
    ///
    /// If none, "NO NAME   "
    VolLab: [11]u8,
    /// One of the strings
    /// "FAT12   "
    /// "FAT16   "
    /// "FAT     "
    FilSysType: [8]u8,
    ///set to 0x55 and 0xAA.
    Signature_word: u16 = 0x55AA,

    pub fn read(file: std.fs.File, offset: u64) !BPB_Extended_1216 {
        var ret: BPB_Extended_1216 = undefined;

        try file.seekTo(offset);

        const self_ti: std.builtin.Type.Struct = @typeInfo(BPB_Extended_1216).Struct;

        var curr_offset: usize = 0;
        inline for (self_ti.fields) |field| {
            const f: std.builtin.Type.StructField = field;
            try file.seekTo(offset + curr_offset);

            switch (@typeInfo(f.type)) {
                .Int => |I| {
                    const size: usize = I.bits / 8;
                    var buf: [size]u8 = undefined;
                    if (try file.read(&buf) != size) return error.EndOfFile;

                    const number: f.type = std.mem.readIntSlice(f.type, &buf, .Little);
                    @field(ret, f.name) = number;
                    curr_offset += size;
                },
                .Array => |arr| {
                    var buf: [arr.len]u8 = undefined;
                    if (try file.read(&buf) != arr.len) return error.EndOfFile;

                    @memcpy(&@field(ret, f.name), &buf);
                    curr_offset += arr.len;

                    if (std.mem.startsWith(u8, f.name, "FilSysType")) {
                        curr_offset += 448;
                    }
                },
                else => unreachable,
            }
        }

        return ret;
    }
};

/// Extend BPB for FAT32
pub const BPB_Extended_32 = struct {
    FATSz32: u32,
    ExtFlags: u16,
    FSVer: u16,
    RootClus: u32,
    FSInfo: u16,
    BkBootSec: u16,
    Reserved: [12]u8,
    /// Only relevent for interrupt 0x13.
    /// 0x80 or 0x00
    DrvNum: u8,
    /// Set to 0.
    Reserved1: u8,
    /// Set to 0x29 if VolID or VolLab are present.
    BootSig: u8,
    /// Volumne Serial Number
    VolID: u32,
    /// Volume Label.
    ///
    /// If none, "NO NAME   "
    VolLab: [11]u8,
    /// "FAT32   "
    FilSysType: [8]u8,
    ///set to 0x55 and 0xAA.
    Signature_word: u16 = 0x55AA,

    pub fn read(file: std.fs.File, offset: u64) !BPB_Extended_32 {
        var ret: BPB_Extended_32 = undefined;

        try file.seekTo(offset);

        const self_ti: std.builtin.Type.Struct = @typeInfo(BPB_Extended_32).Struct;

        var curr_offset: usize = 0;
        inline for (self_ti.fields) |field| {
            const f: std.builtin.Type.StructField = field;
            try file.seekTo(offset + curr_offset);

            switch (@typeInfo(f.type)) {
                .Int => |I| {
                    const size: usize = I.bits / 8;
                    var buf: [size]u8 = undefined;
                    if (try file.read(&buf) != size) return error.EndOfFile;

                    const number: f.type = std.mem.readIntSlice(f.type, &buf, .Little);
                    @field(ret, f.name) = number;
                    curr_offset += size;
                },
                .Array => |arr| {
                    var buf: [arr.len]u8 = undefined;
                    if (try file.read(&buf) != arr.len) return error.EndOfFile;
                    @memcpy(&@field(ret, f.name), &buf);
                    curr_offset += arr.len;

                    if (std.mem.startsWith(u8, f.name, "FilSysType")) {
                        curr_offset += 420;
                    }
                },
                else => unreachable,
            }
        }

        return ret;
    }
};