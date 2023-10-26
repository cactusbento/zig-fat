//! Based off of "Microsoft FAT Specification"
//! https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
const std = @import("std");

/// See "Section 3: Boot Sector and BPB"
pub const BootSector = struct {
    /// See "Secion 3.1"
    bpb_common: BPB_common,
    bpb_extended: ExtentUnion,

    /// See "Section 3.2" and "Section 3.3"
    pub const ExtentUnion = union(enum) {
        fat1216: BPB_Extended_1216,
        fat32: BPB_Extended_32,
    };

    pub fn read(file: std.fs.File) !BootSector {
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

test "BootSector16" {
    var fat16 = try std.fs.cwd().openFile("testFat16.iso", .{});
    defer fat16.close();

    const bs = try BootSector.read(fat16);
    std.debug.print("\n{any}\n{any}\n", .{ bs.bpb_common, bs.bpb_extended });
}
test "BootSector32" {
    var fat32 = try std.fs.cwd().openFile("testFat32.iso", .{});
    defer fat32.close();

    const bs = try BootSector.read(fat32);
    std.debug.print("\n{any}\n{any}\n", .{ bs.bpb_common, bs.bpb_extended });
}

/// Only needed on FAT32
/// See "Section 5: File System Information (FSInfo) Structure"
pub const FSInfoSector = struct {
    pub const valid_lead_signature: u32 = 0x41615252;
    pub const valid_struct_signature: u32 = 0x61417272;
    pub const valid_trail_signature: u32 = 0xAA550000;
    /// Lead signature used to validate the beginning of the FSInfo Structure.
    LeadSig: u32 = valid_lead_signature,

    // Just skip 480 bytes when reading.
    // Reserved1: [480]u8,

    /// Additional signature validating the integrity of the FSInfo structure.
    StrucSig: u32 = valid_struct_signature,

    /// Counts the last known free cluster count on the volume.
    ///
    /// The value 0xFFFFFFFF indicates that the free cluster count is unknown.
    Free_Count: u32,

    Nxt_Free: u32,

    ///Trail Signature used to validate the integrity of the FSInfo Sector.
    TrailSig: u32 = valid_trail_signature,

    /// FSInfoSector is always found in sector 1.
    pub fn read(file: std.fs.File, bs: BootSector) !FSInfoSector {
        var ret: FSInfoSector = undefined;

        const offset = bs.bpb_common.BytsPerSec;

        try file.seekTo(offset);

        const self_ti: std.builtin.Type.Struct = @typeInfo(FSInfoSector).Struct;

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
                else => unreachable,
            }

            if (std.mem.startsWith(u8, f.name, "LeadSig")) {
                curr_offset += 480;
            }
            if (std.mem.startsWith(u8, f.name, "Nxt_Free")) {
                curr_offset += 12;
            }
        }

        return ret;
    }
};

test "FAT32FSInfo" {
    var fat32 = try std.fs.cwd().openFile("testFat32.iso", .{});
    defer fat32.close();

    const bs = try BootSector.read(fat32);
    const fsinfo = try FSInfoSector.read(fat32, bs);

    std.debug.print("\n{}\n", .{fsinfo});
}

/// See "Section 4: FAT"
pub const FileAllocationTable = union(enum) {
    //! The first two entries are reserved
    //! Table[0] & 0xF8
    //! Table[1] & 0xFF
    fat16: []u16,
    fat32: []u32,

    /// Use Deinit to free FAT table.
    pub fn readTable(allocator: std.mem.Allocator, file: std.fs.File, bs: BootSector) !FileAllocationTable {
        // Offset of the first FAT table
        const fat_offset = bs.bpb_common.RsvdSecCnt * bs.bpb_common.BytsPerSec;
        const fat_size = bs.bpb_common.BytsPerSec * switch (bs.bpb_extended) {
            .fat1216 => bs.bpb_common.FATSz16,
            .fat32 => bs.bpb_extended.fat32.FATSz32,
        };

        var ret: FileAllocationTable = switch (bs.bpb_extended) {
            .fat1216 => .{ .fat16 = try allocator.alloc(u16, fat_size / 2) },
            .fat32 => .{ .fat32 = try allocator.alloc(u32, fat_size / 4) },
        };

        try file.seekTo(fat_offset);
        const reader = file.reader();

        switch (ret) {
            inline else => |slice| {
                for (slice) |*v| {
                    v.* = try reader.readIntLittle(@TypeOf(v.*));
                }
            },
        }
        return ret;
    }

    pub fn deinit(self: *FileAllocationTable, allocator: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |s| allocator.free(s),
        }
    }
};

test "FAT16Table" {
    const alloc = std.testing.allocator;
    var fat16 = try std.fs.cwd().openFile("testFat16.iso", .{});
    defer fat16.close();

    const bs = try BootSector.read(fat16);
    var table = try FileAllocationTable.readTable(alloc, fat16, bs);
    defer table.deinit(alloc);

    std.debug.print("\nFAT16 Table\n", .{});
    for (table.fat16, 0..) |entry, i| {
        std.debug.print("{x:0>4} ", .{
            entry,
        });
        if (i > 256) break;
    }
    std.debug.print("\n", .{});
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
    var fat16 = try std.fs.cwd().openFile("testFat16.iso", .{});
    defer fat16.close();

    var fat32 = try std.fs.cwd().openFile("testFat32.iso", .{});
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

pub const LongFileName = struct {};
