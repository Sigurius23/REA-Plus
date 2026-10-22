/* IMPERATIVE_ORIGINAL_OR_COPYRIGHT_NOTICE
 * Copyright (C) 2026 REA+ contributors
 * SPDX-License-Identifier: MIT
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Ghidra's DEX loader symbolizes string-pool items but leaves their bytes
 * defined only as structural string_data_item records, so defined-data string
 * inventories miss every pool value. This preparation redefines one UTF-8
 * string item per pool entry over the loader-mapped .dex block before
 * auto-analysis runs. The original file is never written.
 */
public class ReaGhidraPrepareDex extends GhidraScript {
	/** Session snapshots read bounded pools; hostile files are skipped, not selected. */
	private static final int DEX_HEADER_MIN = 0x70;
	private static final int MAX_POOL_ENTRIES = 2_000_000;
	private static final int MAX_CLEARED_BYTES = 0x1000000;

	@Override
	public void run() throws Exception {
		Memory memory = currentProgram.getMemory();
		if (!currentProgram.getLanguageID().getIdAsString().startsWith("Dalvik:")) {
			println("ReaGhidraPrepareDex: non-Dalvik program; preparation skipped");
			return;
		}
		MemoryBlock dex = memory.getBlock(".dex");
		if (dex == null) {
			println("ReaGhidraPrepareDex: program has no .dex block; preparation skipped");
			return;
		}
		long base = dex.getStart().getOffset();
		long fileSize = dex.getSize();
		if (fileSize < DEX_HEADER_MIN) {
			println("ReaGhidraPrepareDex: .dex block smaller than a DEX header; preparation skipped");
			return;
		}
		long poolCount;
		long poolOffset;
		try {
			poolCount = Integer.toUnsignedLong(memory.getInt(addr(base + 0x38)));
			poolOffset = Integer.toUnsignedLong(memory.getInt(addr(base + 0x3c)));
		} catch (Throwable cause) {
			println("ReaGhidraPrepareDex: unreadable DEX header; preparation skipped");
			return;
		}
		if (poolCount == 0 || poolCount > MAX_POOL_ENTRIES || poolOffset < 0x40) {
			println("ReaGhidraPrepareDex: pool declaration " + poolCount + " entries at 0x"
				+ Long.toHexString(poolOffset) + " is outside the prepared range; preparation skipped");
			return;
		}
		if (poolOffset + poolCount * 4 > fileSize) {
			println("ReaGhidraPrepareDex: pool id table exceeds the .dex block; preparation skipped");
			return;
		}
		Listing listing = currentProgram.getListing();
		StringUTF8DataType utf8 = new StringUTF8DataType();
		long defined = 0;
		for (long index = 0; index < poolCount; index++) {
			monitor.checkCancelled();
			Data created = definePoolString(memory, listing, utf8, base, fileSize,
				poolOffset + index * 4);
			if (created != null) defined++;
		}
		println("ReaGhidraPrepareDex: defined " + defined + " of " + poolCount + " string-pool items");
	}

	/**
	 * Creates one string Data over the pool entry's NUL-terminated MUTF-8
	 * bytes. Duplicate ids sharing one string_data_item are handled once;
	 * the loader's structural record there is cleared first.
	 */
	private Data definePoolString(Memory memory, Listing listing, StringUTF8DataType utf8,
			long base, long fileSize, long idOffset) {
		try {
			long dataOffset = Integer.toUnsignedLong(memory.getInt(addr(base + idOffset)));
			if (dataOffset < 0x40 || dataOffset >= fileSize) return null;
			// string_data_item = uleb128 utf16_size, then NUL-terminated MUTF-8 bytes.
			long payloadOffset = dataOffset;
			while (payloadOffset < fileSize) {
				int octet = memory.getByte(addr(base + payloadOffset)) & 0xff;
				payloadOffset++;
				if ((octet & 0x80) == 0) break;
				if (payloadOffset - dataOffset > 5) return null;
			}
			long length = 0;
			while (payloadOffset + length <= fileSize
				&& memory.getByte(addr(base + payloadOffset + length)) != 0) {
				length++;
			}
			if (payloadOffset + length > fileSize || length == 0) return null;
			Address start = addr(base + payloadOffset);
			Address replacingStart = addr(base + dataOffset);
			Address replacingEnd = addr(base + payloadOffset + length);
			if (listing.getDataAt(replacingStart) != null) {
				listing.clearCodeUnits(replacingStart, replacingEnd, false, monitor);
			}
			Data created = listing.createData(start, utf8, (int) length + 1);
			return created;
		} catch (Throwable cause) {
			println("ReaGhidraPrepareDex: pool definition failed at " + idOffset + ": " + cause);
			return null;
		}
	}

	private Address addr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}
