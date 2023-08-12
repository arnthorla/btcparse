const std = @import("std");
const mem = std.mem;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const assert = std.debug.assert;
const Sha256oSha256 = std.crypto.hash.composition.Sha256oSha256;

const MAX_BLOCKFILE_SIZE: usize = 134_217_728;
const MAX_BLOCK_SIZE: usize = 1_048_576;
const MAX_CMD_LINE_SIZE: usize = 512;
const MAX_PATH_SIZE: usize = 256;

// Formatting
const TABSIZE: usize = 2;

const Format = enum {
    text,
    json_readable,
    json_minify,
    pub fn isJson(self: Format) bool {
        return self != Format.text;
    }
    pub fn isJsonReadable(self: Format) bool {
        return self == Format.json_readable;
    }
    pub fn isJsonMinify(self: Format) bool {
        return self == Format.json_minify;
    }
};

// Bitcoin VarInt
const VarInt = u64;

// Messages:
const msg_usage =
    \\
    \\Usage: btcparse <file|directory> [output-directory]
    \\       btcparse < <file>
    \\       <input-stream> | btcparse
    \\
    \\Notes: - Outputs to current working directory (CWD) by default.
    \\       - output-directory must exist.
    \\
    \\Examples:
    \\      btcparse blocks/blk00000.dat
    \\          Outputs blk00000.out file in CWD.
    \\
    \\      btcparse blocks 
    \\          Parses all .dat files in "blocks" directory.
    \\          Outputs corrisponding .out files in CWD.  
    \\
    \\      btcparse blocks/blk00000.dat outdir
    \\          Same as above except outputs are stored in outdir.
    \\ 
    \\      cat blocks/blk00000.dat | btcparse
    \\          Parses input stream and outputs to stdout.
    \\
    \\      btcparse < blocks/blk00000.dat
    \\          Pareses file and outputs to stdout.
    \\
;

// Transaction Inputs
const Tx_In = struct {
    txid: [32]u8,
    vout: [4]u8,
    script_length: VarInt,
    script_sig: []u8,
    sequence: [4]u8,
    pub fn init() Tx_In {
        return Tx_In{
            .txid = [_]u8{0} ** 32,
            .vout = [_]u8{0} ** 4,
            .script_length = 0,
            .script_sig = undefined,
            .sequence = [_]u8{0} ** 4,
        };
    }
    pub fn format(
        self: Tx_In,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("{{", .{});
            try writer.print("\"txid\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.txid)});
            try writer.print("\"script_length\":\"{d}\",", .{self.script_length});
            try writer.print("\"script_sig\":\"{s}\",", .{std.fmt.fmtSliceHexLower(self.script_sig)});
            try writer.print("\"sequence\":\"{s}\"", .{std.fmt.fmtSliceHexLower(&self.sequence)});
            try writer.print("}}", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}{{\n", .{" " ** (TABSIZE * 5)});
            try writer.print("{s}\"txid\": \"{s}\",\n", .{ " " ** (TABSIZE * 6), std.fmt.fmtSliceHexLower(&self.txid) });
            try writer.print("{s}\"script_length\": \"{d}\",\n", .{ " " ** (TABSIZE * 6), self.script_length });
            try writer.print("{s}\"script_sig\": \"{s}\",\n", .{ " " ** (TABSIZE * 6), std.fmt.fmtSliceHexLower(self.script_sig) });
            try writer.print("{s}\"sequence\": \"{s}\"\n", .{ " " ** (TABSIZE * 6), std.fmt.fmtSliceHexLower(&self.sequence) });
            try writer.print("{s}}}", .{" " ** (TABSIZE * 5)});
        } else {
            try writer.print("{s}TXID: \t\t{s}\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(&self.txid) });
            try writer.print("{s}Script length: {d}\n", .{ " " ** (TABSIZE * 2), self.script_length });
            try writer.print("{s}ScriptSig:\t{s}\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(self.script_sig) });
            try writer.print("{s}Sequence:\t{s}\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(&self.sequence) });
        }
    }
};

// Transaction Outputs
const Tx_Out = struct {
    value: u64,
    script_length: VarInt,
    script_pub_key: []u8,
    pub fn init() Tx_Out {
        return Tx_Out{
            .value = 0,
            .script_length = 0,
            .script_pub_key = undefined,
        };
    }
    pub fn format(
        self: Tx_Out,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("{{", .{});
            try writer.print("\"value\":\"{d}\",", .{self.value});
            try writer.print("\"script_length\":\"{d}\",", .{self.script_length});
            try writer.print("\"script_pubkey\":\"{s}\"", .{std.fmt.fmtSliceHexLower(self.script_pub_key)});
            try writer.print("}}", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}{{\n", .{" " ** (TABSIZE * 5)});
            try writer.print("{s}\"value\": \"{d}\",\n", .{ " " ** (TABSIZE * 6), self.value });
            try writer.print("{s}\"script_length\": \"{d}\",\n", .{ " " ** (TABSIZE * 6), self.script_length });
            try writer.print("{s}\"script_pubkey\": \"{s}\"\n", .{ " " ** (TABSIZE * 6), std.fmt.fmtSliceHexLower(self.script_pub_key) });
            try writer.print("{s}}}", .{" " ** (TABSIZE * 5)});
        } else {
            try writer.print("{s}Value (satoshis): {d}\n", .{ " " ** (TABSIZE * 2), self.value });
            try writer.print("{s}Script length: {d}\n", .{ " " ** (TABSIZE * 2), self.script_length });
            try writer.print("{s}ScriptPubKey: {s}\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(self.script_pub_key) });
        }
    }
};

const WitnessComp = struct {
    length: VarInt,
    comp: []u8,
    pub fn init() WitnessComp {
        return WitnessComp{
            .length = 0,
            .comp = undefined,
        };
    }
    pub fn format(
        self: WitnessComp,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("{{", .{});
            try writer.print("\"length\":\"{d}\",", .{self.length});
            try writer.print("\"comp\":\"{s}\"", .{std.fmt.fmtSliceHexLower(self.comp)});
            try writer.print("}}", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}{{\n", .{" " ** (TABSIZE * 6)});
            try writer.print("{s}\"length\": \"{d}\",\n", .{ " " ** (TABSIZE * 7), self.length });
            try writer.print("{s}\"comp\": \"{s}\"\n", .{ " " ** (TABSIZE * 7), std.fmt.fmtSliceHexLower(self.comp) });
            try writer.print("\n{s}}}", .{" " ** (TABSIZE * 6)});
        } else {
            try writer.print("{s}WitnessComp length[{d}]:\n", .{ " " ** (TABSIZE * 3), self.length });
            try writer.print("{s}WitnesComp: {s}\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(self.comp) });
        }
    }
};

const Witness = struct {
    count: VarInt,
    witnesses: []WitnessComp,
    pub fn init() Witness {
        return Witness{
            .count = 0,
            .witnesses = undefined,
        };
    }
    pub fn format(
        self: Witness,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("\"witness\":{{", .{});
            try writer.print("\"witness_cnt\":\"{d}\",", .{self.count});
            try writer.print("\"witnesses\":[", .{});
            var first: bool = true;
            for (self.witnesses) |w| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",", .{});
                }
                try writer.print("{j}", .{w});
            }
            try writer.print("]", .{});
            try writer.print("}},", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}\"witness\": {{\n", .{" " ** (TABSIZE * 4)});
            try writer.print("{s}\"witness_cnt\": \"{d}\",\n", .{ " " ** (TABSIZE * 5), self.count });
            try writer.print("{s}\"witnesses\": [\n", .{" " ** (TABSIZE * 5)});
            var first: bool = true;
            for (self.witnesses) |w| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",\n", .{});
                }
                try writer.print("{J}", .{w});
            }
            try writer.print("\n{s}]\n", .{" " ** (TABSIZE * 5)});
            try writer.print("{s}}},\n", .{" " ** (TABSIZE * 4)});
        } else {
            try writer.print("{s}Witness:\n", .{" " ** (TABSIZE * 1)});
            try writer.print("{s}#Witnesses: {d}\n", .{ " " ** (TABSIZE * 2), self.count });
            var i: usize = 0;
            for (self.witnesses) |w| {
                try writer.print("{s}WitnessComp[{d}]:\n", .{ " " ** (TABSIZE * 2), i });
                try writer.print("{s}", .{w});
                i += 1;
            }
        }
    }
};

const Tx = struct {
    version: [4]u8,
    has_witness: bool = false, // not in protocol
    witness_flags: [4]u8 = [4]u8{ 0, 0, 0, 0 },
    tx_in_count: VarInt,
    tx_in: []Tx_In,
    tx_out_count: VarInt,
    tx_out: []Tx_Out,
    witness: Witness,
    locktime: [4]u8,
    pub fn init() Tx {
        return Tx{
            .version = [_]u8{0} ** 4,
            .has_witness = false,
            .witness_flags = [_]u8{0} ** 4,
            .tx_in_count = 0,
            .tx_in = undefined,
            .tx_out_count = 0,
            .tx_out = undefined,
            .witness = undefined,
            .locktime = [_]u8{0} ** 4,
        };
    }
    pub fn format(
        self: Tx,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("{{", .{});
            try writer.print("\"version\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.version)});
            if (self.has_witness) {
                try writer.print("\"witness_flags\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.witness_flags)});
            }
            try writer.print("\"tx_in_cnt\":\"{d}\",", .{self.tx_in_count});
            try writer.print("\"tx_ins\":[", .{});
            var first: bool = true;
            for (self.tx_in) |tx_in| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",", .{});
                }
                try writer.print("{j}", .{tx_in});
            }
            try writer.print("],", .{});
            try writer.print("\"tx_out_cnt\":\"{d}\",", .{self.tx_out_count});
            try writer.print("\"tx_outs\":[", .{});
            first = true;
            for (self.tx_out) |tx_out| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",", .{});
                }
                try writer.print("{j}", .{tx_out});
            }
            try writer.print("],", .{});
            if (self.has_witness) {
                try writer.print("{j}", .{self.witness});
            }
            try writer.print("\"locktime\":\"{s}\"", .{std.fmt.fmtSliceHexLower(&self.locktime)});
            try writer.print("}}", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}{{\n", .{" " ** (TABSIZE * 3)});
            try writer.print("{s}\"version\": \"{s}\",\n", .{ " " ** (TABSIZE * 4), std.fmt.fmtSliceHexLower(&self.version) });
            if (self.has_witness) {
                try writer.print("{s}\"witness_flags\": \"{s}\",\n", .{ " " ** (TABSIZE * 4), std.fmt.fmtSliceHexLower(&self.witness_flags) });
            }
            try writer.print("{s}\"tx_in_cnt\": \"{d}\",\n", .{ " " ** (TABSIZE * 4), self.tx_in_count });
            try writer.print("{s}\"tx_ins\": [\n", .{" " ** (TABSIZE * 4)});
            var first: bool = true;
            for (self.tx_in) |tx_in| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",\n", .{});
                }
                try writer.print("{J}", .{tx_in});
            }
            try writer.print("\n{s}],\n", .{" " ** (TABSIZE * 4)});
            try writer.print("{s}\"tx_out_cnt\": \"{d}\",\n", .{ " " ** (TABSIZE * 4), self.tx_out_count });
            try writer.print("{s}\"tx_outs\": [\n", .{" " ** (TABSIZE * 4)});
            first = true;
            for (self.tx_out) |tx_out| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",\n", .{});
                }
                try writer.print("{J}", .{tx_out});
            }
            try writer.print("\n{s}],\n", .{" " ** (TABSIZE * 4)});
            if (self.has_witness) {
                try writer.print("{J}", .{self.witness});
            }
            try writer.print("{s}\"locktime\": \"{s}\"\n", .{ " " ** (TABSIZE * 4), std.fmt.fmtSliceHexLower(&self.locktime) });
            try writer.print("{s}}}", .{" " ** (TABSIZE * 3)});
        } else {
            try writer.print("{s}Version: \t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.version) });
            if (self.has_witness) {
                try writer.print("{s}Witness flags: \t\t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.witness_flags) });
            }
            try writer.print("{s}#Tx_In: {d}\n", .{ " " ** (TABSIZE * 1), self.tx_in_count });
            var tx_in_i: usize = 0;
            for (self.tx_in) |tx_in| {
                try writer.print("{s}Tx_In[{d}]:\n", .{ " " ** (TABSIZE * 1), tx_in_i });
                try writer.print("{s}", .{tx_in});
                tx_in_i += 1;
            }
            try writer.print("{s}#Tx_Out: {d}\n", .{ " " ** (TABSIZE * 1), self.tx_out_count });
            var tx_out_i: usize = 0;
            for (self.tx_out) |tx_out| {
                try writer.print("{s}Tx_Out[{d}]:\n", .{ " " ** (TABSIZE * 1), tx_out_i });
                try writer.print("{s}", .{tx_out});
                tx_out_i += 1;
            }
            if (self.has_witness) {
                try writer.print("{s}Witness:\n", .{" " ** (TABSIZE * 1)});
                try writer.print("{s}", .{self.witness});
            }
            try writer.print("{s}Locktime:\t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.locktime) });
        }
    }
};

const BlockHeader = struct {
    version: [4]u8,
    prev_block: [32]u8,
    merkle_root: [32]u8,
    timestamp: [4]u8,
    difficulty: [4]u8,
    nonce: [4]u8,
    pub fn init() BlockHeader {
        return BlockHeader{
            .version = [4]u8{ 0, 0, 0, 0 },
            .prev_block = [_]u8{0} ** 32,
            .merkle_root = [_]u8{0} ** 32,
            .timestamp = [4]u8{ 0, 0, 0, 0 },
            .difficulty = [4]u8{ 0, 0, 0, 0 },
            .nonce = [4]u8{ 0, 0, 0, 0 },
        };
    }
    pub fn format(
        self: BlockHeader,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("\"header\":{{", .{});
            try writer.print("\"version\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.version)});
            try writer.print("\"prev_block\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.prev_block)});
            try writer.print("\"merkle root\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.merkle_root)});
            try writer.print("\"timestamp\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.timestamp)});
            try writer.print("\"difficulty\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.difficulty)});
            try writer.print("\"nonce\":\"{s}\"", .{std.fmt.fmtSliceHexLower(&self.nonce)});
            try writer.print("}},", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}\"header\": {{\n", .{" " ** (TABSIZE * 2)});
            try writer.print("{s}\"version\": \"{s}\",\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.version) });
            try writer.print("{s}\"prev_block\": \"{s}\",\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.prev_block) });
            try writer.print("{s}\"merkle root\": \"{s}\",\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.merkle_root) });
            try writer.print("{s}\"timestamp\": \"{s}\",\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.timestamp) });
            try writer.print("{s}\"difficulty\": \"{s}\",\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.difficulty) });
            try writer.print("{s}\"nonce\": \"{s}\"\n", .{ " " ** (TABSIZE * 3), std.fmt.fmtSliceHexLower(&self.nonce) });
            try writer.print("{s}}},\n", .{" " ** (TABSIZE * 2)});
        } else {
            try writer.print("{s}Version: \t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.version) });
            try writer.print("{s}Hash of previous block: {s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.prev_block) });
            try writer.print("{s}Merkle root:\t\t  {s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.merkle_root) });
            try writer.print("{s}Timestamp: \t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.timestamp) });
            try writer.print("{s}Difficulty: \t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.difficulty) });
            try writer.print("{s}Nonce: \t{s}\n", .{ " " ** (TABSIZE * 1), std.fmt.fmtSliceHexLower(&self.nonce) });
        }
    }
};

const Block = struct {
    magic_bytes: [4]u8,
    size: VarInt,
    hash_current_header: [32]u8,
    block_header: BlockHeader,
    tx_count: VarInt,
    txs: []Tx,
    pub fn init() Block {
        return Block{
            .magic_bytes = [4]u8{ 0, 0, 0, 0 },
            .size = 0,
            .hash_current_header = [_]u8{0} ** 32,
            .block_header = undefined,
            .tx_count = 0,
            .txs = undefined,
        };
    }
    pub fn format(
        self: Block,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (comptime std.mem.eql(u8, fmt, "j")) {
            try writer.print("{{", .{});
            try writer.print("\"hash\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.hash_current_header)});
            try writer.print("\"magic_bytes\":\"{s}\",", .{std.fmt.fmtSliceHexLower(&self.magic_bytes)});
            try writer.print("\"size\":\"{d}\",", .{self.size});
            try writer.print("{j}", .{self.block_header});
            try writer.print("\"tx_cnt\":\"{d}\",", .{self.tx_count});
            try writer.print("\"txs\":[", .{});
            var first: bool = true;
            for (self.txs) |tx| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",", .{});
                }
                try writer.print("{j}", .{tx});
            }
            try writer.print("]", .{});
            try writer.print("}}", .{});
        } else if (comptime std.mem.eql(u8, fmt, "J")) {
            try writer.print("{s}{{\n", .{" " ** (TABSIZE * 1)});
            try writer.print("{s}\"hash\": \"{s}\",\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(&self.hash_current_header) });
            try writer.print("{s}\"magic_bytes\": \"{s}\",\n", .{ " " ** (TABSIZE * 2), std.fmt.fmtSliceHexLower(&self.magic_bytes) });
            try writer.print("{s}\"size\": \"{d}\",\n", .{ " " ** (TABSIZE * 2), self.size });
            try writer.print("{J}", .{self.block_header});
            try writer.print("{s}\"tx_cnt\": \"{d}\",\n", .{ " " ** (TABSIZE * 2), self.tx_count });
            try writer.print("{s}\"txs\": [\n", .{" " ** (TABSIZE * 2)});
            var first: bool = true;
            for (self.txs) |tx| {
                if (first) {
                    first = false;
                } else {
                    try writer.print(",\n", .{});
                }
                try writer.print("{J}", .{tx});
            }
            try writer.print("\n{s}]\n", .{" " ** (TABSIZE * 2)});
            try writer.print("{s}}}", .{" " ** (TABSIZE * 1)});
        } else {
            try writer.print("{s}Block hash: {s}\n", .{ " " ** (TABSIZE * 0), std.fmt.fmtSliceHexLower(&self.hash_current_header) });
            try writer.print("{s}Magic bytes(network): {s}\n", .{ " " ** (TABSIZE * 0), std.fmt.fmtSliceHexLower(&self.magic_bytes) });
            try writer.print("{s}Block size: {d}\n", .{ " " ** (TABSIZE * 0), self.size });
            try writer.print("{s}Block header:\n", .{" " ** (TABSIZE * 0)});
            try writer.print("{s}", .{self.block_header});
            try writer.print("{s}Number of Transactions: {d}\n", .{ " " ** (TABSIZE * 0), self.tx_count });
            var tx_i: usize = 0;
            for (self.txs) |tx| {
                try writer.print("{s}Tx[{d}]:\n", .{ " " ** (TABSIZE * 0), tx_i });
                try writer.print("{tx}", .{tx});
                tx_i += 1;
            }
        }
    }
};

fn getVarInt(buf: []u8, index: *usize) VarInt {
    var i = index.*;
    var res = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

    switch (buf[i]) {
        0...252 => {
            res[0] = buf[i];
            index.* = i + 1;
        },
        253 => {
            res[0] = buf[i + 1];
            res[1] = buf[i + 2];
            index.* = i + 3;
        },
        254 => {
            res[0] = buf[i + 1];
            res[1] = buf[i + 2];
            res[2] = buf[i + 3];
            res[3] = buf[i + 4];
            index.* = i + 5;
        },
        255 => {
            res[0] = buf[i + 1];
            res[1] = buf[i + 2];
            res[2] = buf[i + 3];
            res[3] = buf[i + 4];
            res[4] = buf[i + 5];
            res[5] = buf[i + 6];
            res[6] = buf[i + 7];
            res[7] = buf[i + 8];
            index.* = i + 9;
        },
    }
    return @bitCast(u64, res);
}

fn getValue(buf: []u8, index: *usize) u64 {
    var i = index.*;
    var res = [_]u8{0} ** 8;
    mem.copy(u8, &res, buf[i .. i + 8]);
    i += 8;
    index.* = i;

    return @bitCast(u64, res);
}

fn copyReverse(dest: []u8, source: []const u8) void {
    @setRuntimeSafety(false);
    assert(dest.len >= source.len);
    var i: usize = 0;
    var j: usize = source.len - 1;
    while (i < source.len) {
        dest[i] = source[j];
        i += 1;
        j -= 1;
    }
}

fn reverse(bytes: []u8, size: usize) void {
    var i: usize = 0;
    var j: usize = size - 1;
    while (i < j) { // swap bytes
        bytes[i] = bytes[i] ^ bytes[j];
        bytes[j] = bytes[i] ^ bytes[j]; // bytes[i]
        bytes[i] = bytes[i] ^ bytes[j]; // bytes[j]
        i += 1;
        j -= 1;
    }
}

fn parceWitness(raw_block: []u8, index: *usize, witness: *Witness, allocator: anytype) !void {
    var i: usize = index.*;
    witness.* = Witness.init();
    witness.count = getVarInt(raw_block, &i);
    witness.witnesses = try allocator.alloc(WitnessComp, witness.count);
    for (witness.witnesses) |*witnessComp| {
        witnessComp.* = WitnessComp.init();
        witnessComp.length = getVarInt(raw_block, &i);
        mem.copy(u8, witnessComp.comp, raw_block[i .. i + witnessComp.length]);
        i += witnessComp.length;
    }
    index.* = i;
}

fn parceTx(raw_block: []u8, index: *usize, num_txs: usize, allocator: anytype) ![]Tx {
    var i: usize = index.*;
    var txs: []Tx = try allocator.alloc(Tx, num_txs);
    for (txs) |*tx| {
        tx.* = Tx.init();
        copyReverse(&tx.version, raw_block[i .. i + 4]);
        i += 4;
        if (raw_block[i] == 0) { // has witness
            tx.has_witness = true;
            mem.copy(u8, &tx.witness_flags, raw_block[i .. i + 4]);
            i += 4;
        }
        tx.tx_in_count = getVarInt(raw_block, &i);
        tx.tx_in = try allocator.alloc(Tx_In, tx.tx_in_count);
        for (tx.tx_in) |*tx_in| {
            tx_in.* = Tx_In.init();
            copyReverse(&tx_in.txid, raw_block[i .. i + 32]);
            i += 32;
            copyReverse(&tx_in.vout, raw_block[i .. i + 4]);
            i += 4;
            tx_in.script_length = getVarInt(raw_block, &i);
            tx_in.script_sig = try allocator.alloc(u8, tx_in.script_length);
            mem.copy(u8, tx_in.script_sig, raw_block[i .. i + tx_in.script_length]);
            i += tx_in.script_length;
            copyReverse(&tx_in.sequence, raw_block[i .. i + 4]);
            i += 4;
        }
        tx.tx_out_count = getVarInt(raw_block, &i);
        tx.tx_out = try allocator.alloc(Tx_Out, tx.tx_out_count);
        for (tx.tx_out) |*tx_out| {
            tx_out.* = Tx_Out.init();
            tx_out.value = getValue(raw_block, &i);
            tx_out.script_length = getVarInt(raw_block, &i);
            tx_out.script_pub_key = try allocator.alloc(u8, tx_out.script_length);
            mem.copy(u8, tx_out.script_pub_key, raw_block[i .. i + tx_out.script_length]);
            i += tx_out.script_length;
        }
        if (tx.has_witness) {
            try parceWitness(raw_block, &i, &tx.witness, allocator);
        }
        copyReverse(&tx.locktime, raw_block[i .. i + 4]);
        i += 4;
    }
    index.* = i;

    return txs;
}

fn hash256_BlockHeader(raw_block: []u8, index: usize) [32]u8 {
    var res: [32]u8 = [_]u8{0} ** 32;
    Sha256oSha256.hash(raw_block[index .. index + 80], &res, .{});
    reverse(&res, 32);

    return res;
}

fn parceBlockHeader(raw_block: []u8, index: *usize) BlockHeader {
    var i: usize = index.*;
    var header: BlockHeader = BlockHeader.init();
    copyReverse(&header.version, raw_block[i .. i + 4]);
    i += 4;
    copyReverse(&header.prev_block, raw_block[i .. i + 32]);
    i += 32;
    copyReverse(&header.merkle_root, raw_block[i .. i + 32]);
    i += 32;
    copyReverse(&header.timestamp, raw_block[i .. i + 4]);
    i += 4;
    copyReverse(&header.difficulty, raw_block[i .. i + 4]);
    i += 4;
    copyReverse(&header.nonce, raw_block[i .. i + 4]);
    i += 4;
    index.* = i;

    return header;
}

fn parceBlock(magic_bytes: [4]u8, block_size: u64, raw_block: []u8, allocator: anytype) !*Block {
    var index: usize = 0;
    var block: []Block = try allocator.alloc(Block, 1);
    block[0] = Block.init();
    copyReverse(&block[0].magic_bytes, magic_bytes[0..4]);
    block[0].size = block_size;
    block[0].hash_current_header = hash256_BlockHeader(raw_block, index);
    block[0].block_header = parceBlockHeader(raw_block, &index);
    block[0].tx_count = getVarInt(raw_block, &index);
    block[0].txs = try parceTx(raw_block, &index, block[0].tx_count, allocator);

    return &block[0];
}

fn readBlock(magic_bytes: *[4]u8, block_size: *u64, ptr_block: *[]u8, reader: anytype, allocator: anytype) !usize {
    var bytes_read: usize = 0;
    var mb = try reader.readBoundedBytes(4);
    if (mb.len == 0) { // EOF
        return 0;
    }
    bytes_read += 4;
    var raw_size = try reader.readBoundedBytes(4);
    bytes_read += 4;
    const size: u32 = @bitCast(u32, raw_size.buffer);
    const b = try allocator.alloc(u8, size);
    bytes_read += try reader.readAll(b);
    magic_bytes.* = mb.buffer;
    block_size.* = size;
    ptr_block.* = b;

    return bytes_read;
}

fn read(in: anytype, out: anytype, format: Format) !void {
    // Block Memory Allocation: Read & Data struct:
    // Raw block size does not exceed MAX_BLOCK_SIZE.
    // Block data structure can exceed this max.
    // So, we allocate 3x MAX_BLOCK_SIZE to be safe.
    // A safe size is probably much closer to 2x
    // MAX_BLOCK_SIZE.
    // TODO: Analyse and prove a lower safe max.
    // Idea: Max number of structues, with min
    // payload, should result in maximum.
    // Intuition: Maximum wrapping size to content size.
    var buffer: [3 * MAX_BLOCK_SIZE]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = &fba.allocator();

    // Set up buffered reader
    var buf_reader = std.io.bufferedReader(in.reader());
    var reader = buf_reader.reader();

    // Set up buffered writer
    var buf_writer = std.io.bufferedWriter(out.writer());
    var writer = buf_writer.writer();

    // Part of block structure
    var magic_bytes = [4]u8{ 0, 0, 0, 0 };
    var block_size: u64 = 0;
    var raw_block: []u8 = undefined;

    var first: bool = true;
    while (try readBlock(&magic_bytes, &block_size, &raw_block, reader, allocator) > 0) {
        const block = try parceBlock(magic_bytes, block_size, raw_block, allocator);

        if (format.isJson()) {
            switch (format) { 
                .json_minify => {if (first) {try writer.print("[", .{});} else {try writer.print(",", .{});}},
                .json_readable => {if (first) {try writer.print("[\n", .{});} else {try writer.print(",\n", .{});}},
                .text => unreachable,
            }
            first = false;
            switch (format) { 
                .json_minify => try writer.print("{j}", .{block.*}),
                .json_readable => try writer.print("{J}", .{block.*}),
                .text => unreachable,
            }
        } else {
            try writer.print("{s}\n", .{block.*});
        }
        try buf_writer.flush();

        fba.reset(); // re-use memory
    }
    if (format.isJson()) {
        switch (format) { 
            .json_minify => try writer.print("]", .{}),
            .json_readable => try writer.print("\n]", .{}),
            .text => unreachable,
        }
        try buf_writer.flush();
    }
}

fn makeOtputFilename(filename: []const u8, allocator: anytype, format: Format) ![]u8 {
    var out_filename: []u8 = undefined;
    if (format.isJson()) {
        const json_ext = [_]u8{ '.', 'j', 's', 'o', 'n' };
        out_filename = try allocator.alloc(u8, filename.len + 1);
        mem.copy(u8, out_filename, filename);
        mem.copy(u8, out_filename[filename.len - 4 ..], &json_ext);
    } else {
        const out_ext = [_]u8{ '.', 'o', 'u', 't' };
        out_filename = try allocator.alloc(u8, filename.len);
        mem.copy(u8, out_filename, filename);
        mem.copy(u8, out_filename[filename.len - 4 ..], &out_ext);
    }

    return out_filename;
}

fn argsInFilenameOutDir(in_filename: []const u8, out_dir: std.fs.Dir, allocator: anytype, format: Format) !void {
    // Input
    if (!mem.eql(u8, std.fs.path.extension(in_filename), ".dat")) {
        std.debug.print("\"{s}\" is not a .dat file\n", .{in_filename});
        return;
    }
    const in_file = std.fs.cwd().openFile(in_filename, .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    defer in_file.close();

    // Output
    const target_filename = try makeOtputFilename(std.fs.path.basename(in_filename), allocator, format);
    const out_file = out_dir.createFile(target_filename, .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    defer out_file.close();

    try read(in_file, out_file, format);
}

fn argsInDirnameOutDir(in_dirname: []const u8, out_dir: std.fs.Dir, allocator: anytype, fba: *std.heap.FixedBufferAllocator, format: Format) !void {
    var in_dir = std.fs.cwd().openDir(in_dirname, .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    defer in_dir.close();
    var in_itdir = std.fs.cwd().openIterableDir(in_dirname, .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    var iter = in_itdir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind == .File and mem.eql(u8, std.fs.path.extension(entry.name), ".dat")) {
            // Input
            const in_file = in_dir.openFile(entry.name, .{}) catch |err| {
                std.debug.print("{}\n", .{err});
                return;
            };
            defer in_file.close();

            // Output
            const target_filename = try makeOtputFilename(entry.name, allocator, format);
            const out_file = out_dir.createFile(target_filename, .{}) catch |err| {
                std.debug.print("{}\n", .{err});
                return;
            };
            defer out_file.close();

            try read(in_file, out_file, format);
            fba.reset(); // re-use FixedBufferAllocator memory
        }
    }
}

fn singleArg(arg: []const u8, allocator: anytype, fba: *std.heap.FixedBufferAllocator, format: Format) !void {
    var out_dir = std.fs.cwd().openDir(".", .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    defer out_dir.close();
    const arg_stat = try std.fs.cwd().statFile(arg);
    if (arg_stat.kind == .File) {
        try argsInFilenameOutDir(arg, out_dir, allocator, format);
    } else if (arg_stat.kind == .Directory) {
        try argsInDirnameOutDir(arg, out_dir, allocator, fba, format);
    } else {
        std.debug.print("\"{s}\" is neither a file nor a directory\n", .{arg});
        std.debug.print("{s}\n", .{msg_usage});
        return;
    }
}

fn twoArgs(arg1: []const u8, arg2: []const u8, allocator: anytype, fba: *std.heap.FixedBufferAllocator, format: Format) !void {
    const snd_arg_stat = try std.fs.cwd().statFile(arg2);
    if (snd_arg_stat.kind != .Directory) {
        std.debug.print("\"{s}\" is not a directory\n", .{arg2});
        std.debug.print("{s}\n", .{msg_usage});
        return;
    }
    var out_dir = std.fs.cwd().openDir(arg2, .{}) catch |err| {
        std.debug.print("{}\n", .{err});
        return;
    };
    defer out_dir.close();

    const fst_arg_stat = try std.fs.cwd().statFile(arg1);
    if (fst_arg_stat.kind == .File) {
        try argsInFilenameOutDir(arg1, out_dir, allocator, format);
    } else if (fst_arg_stat.kind == .Directory) {
        try argsInDirnameOutDir(arg1, out_dir, allocator, fba, format);
    } else {
        std.debug.print("\"{s}\" is neither a file nor a directory\n", .{arg1});
        return;
    }
}

pub fn main() !void {
    // Command Line Memory Allocation:
    var cmdl_buffer: [MAX_CMD_LINE_SIZE]u8 = undefined;
    var cmdl_fba = std.heap.FixedBufferAllocator.init(&cmdl_buffer);
    const cmdl_allocator = cmdl_fba.allocator();

    // Pathname Memory Allocation:
    var path_buffer: [MAX_PATH_SIZE]u8 = undefined;
    var path_fba = std.heap.FixedBufferAllocator.init(&path_buffer);
    const path_allocator = path_fba.allocator();

    // Process Command line arguments:
    const args = try std.process.argsAlloc(cmdl_allocator);
    const args_len = args.len;

    if (args_len == 1) {
        const in = std.io.getStdIn();
        defer in.close();
        const in_stat = try in.stat();
        // Piped '|' or redirected '<' input from command line:
        if (in_stat.kind == .NamedPipe or in_stat.kind == .File) {
            const out = std.io.getStdOut();
            try read(in, out, Format.text);
        } else {
            std.debug.print("{s}\n", .{msg_usage});
        }
    } else if (args_len == 2) {
        if (args[1][0] == '-') { // flag
            if (args[1].len > 1 and (args[1][1] == 'j' or args[1][1] == 'J')) {
                const in = std.io.getStdIn();
                defer in.close();
                const in_stat = try in.stat();
                // Json + Piped '|' or redirected '<' input from command line:
                if (in_stat.kind == .NamedPipe or in_stat.kind == .File) {
                    const out = std.io.getStdOut();
                    switch (args[1][1]) {
                        'j' => try read(in, out, Format.json_minify),
                        'J' => try read(in, out, Format.json_readable),
                        else => unreachable,
                    }
                    return;
                }
            } // other cases treated as help
            std.debug.print("{s}\n", .{msg_usage});
        } else {
            try singleArg(args[1], path_allocator, &path_fba, Format.text);
        }
    } else if (args.len == 3) {
        if (args[1][0] == '-') { // flag
            if (args[1].len > 1 and (args[1][1] == 'j' or args[1][1] == 'J')) {
                switch (args[1][1]) {
                    'j' => try singleArg(args[2], path_allocator, &path_fba, Format.json_minify),
                    'J' => try singleArg(args[2], path_allocator, &path_fba, Format.json_readable),
                    else => unreachable,
                }
            } else { // other cases treated as help
                std.debug.print("{s}\n", .{msg_usage});
            }
        } else {
            try twoArgs(args[1], args[2], path_allocator, &path_fba, Format.text);
        }
    } else {
        if (args[1][0] == '-') { // flag
            if (args[1].len > 1 and (args[1][1] == 'j' or args[1][1] == 'J')) {
                switch (args[1][1]) {
                    'j' => try twoArgs(args[2], args[3], path_allocator, &path_fba, Format.json_minify),
                    'J' => try twoArgs(args[2], args[3], path_allocator, &path_fba, Format.json_readable),
                    else => unreachable,
                }
            } else { // other cases treated as help
                std.debug.print("{s}\n", .{msg_usage});
                return;
            }
        } else {
            std.debug.print("\"{s}\" is not an option.\n", .{args[1]});
            std.debug.print("Expected 3 arguments: [option] <file|directory> <directory>.\n", .{});
            std.debug.print("{s}\n", .{msg_usage});
        }
    }
}

test "test_getVarInt" {
    //               100| 255        | 555       | 70015             | 18_005_558_675_309                  |
    var buf = [_]u8{ 100, 253, 255, 0, 253, 43, 2, 254, 127, 17, 1, 0, 255, 109, 199, 237, 62, 96, 16, 0, 0 };
    var index: usize = 0;
    var res: VarInt = 0;

    res = getVarInt(&buf, &index);
    try expectEqual(@as(u64, 100), res);
    res = getVarInt(&buf, &index);
    try expectEqual(@as(u64, 255), res);
    res = getVarInt(&buf, &index);
    try expectEqual(@as(u64, 555), res);
    res = getVarInt(&buf, &index);
    try expectEqual(@as(u64, 70015), res);
    res = getVarInt(&buf, &index);
    try expectEqual(@as(u64, 18_005_558_675_309), res);
}

test "test_reverse" {
    var bytes = [10]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    reverse(&bytes, 10);

    try expectEqual(bytes, .{ 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 });
}

test "test_copyReverse" {
    var dest = [10]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var source = [10]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    copyReverse(&dest, source[3..7]);

    try expectEqual(dest, .{ 7, 6, 5, 4, 5, 6, 7, 8, 9, 10 });
}
