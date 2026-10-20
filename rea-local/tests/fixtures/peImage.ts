/**
 * Deterministic PE32+ (AMD64) image for pattern-scanning tests. `.text` at
 * RVA 0x1000 loads a pointer from `.data` at RVA 0x2000 and calls a helper:
 *
 *   0x1000  48 8B 05 F9 0F 00 00   mov rax, [rip+0xff9]   ; -> 0x2000
 *   0x1007  48 85 C0               test rax, rax
 *   0x100A  74 05                  je 0x1011
 *   0x100C  E8 EF 00 00 00         call 0x1100
 *   0x1011  C3                     ret
 *   0x1100  31 C0 C3               xor eax, eax; ret
 */
export const PE_IMAGE = Object.freeze({
  imageBase: 0x1_4000_0000n,
  textRva: 0x1000,
  textOffset: 0x200,
  dataRva: 0x2000,
  dataOffset: 0x400,
  helperRva: 0x1100,
  name: "game.exe",
});

const SECTION_SIZE = 0x200;

export const createPeImage = (): Buffer => {
  const file = Buffer.alloc(PE_IMAGE.dataOffset + SECTION_SIZE);
  file.write("MZ", 0, "latin1");
  file.writeUInt32LE(0x40, 0x3c);
  file.write("PE\0\0", 0x40, "latin1");
  file.writeUInt16LE(0x8664, 0x44);
  file.writeUInt16LE(2, 0x46);
  file.writeUInt16LE(240, 0x54);
  file.writeUInt16LE(0x22, 0x56);
  const optional = 0x58;
  file.writeUInt16LE(0x20b, optional);
  file.writeUInt32LE(PE_IMAGE.textRva, optional + 16);
  file.writeBigUInt64LE(PE_IMAGE.imageBase, optional + 24);
  file.writeUInt32LE(0x1000, optional + 32);
  file.writeUInt32LE(0x200, optional + 36);
  file.writeUInt32LE(0x3000, optional + 56);
  file.writeUInt32LE(0x200, optional + 60);
  file.writeUInt16LE(3, optional + 68);
  file.writeUInt32LE(16, optional + 108);
  const sections = [
    [".text", PE_IMAGE.textRva, PE_IMAGE.textOffset, 0x60000020],
    [".data", PE_IMAGE.dataRva, PE_IMAGE.dataOffset, 0xc0000040],
  ] as const;
  sections.forEach(([name, rva, offset, flags], index) => {
    const at = optional + 240 + index * 40;
    file.write(name, at, "latin1");
    file.writeUInt32LE(SECTION_SIZE, at + 8);
    file.writeUInt32LE(rva, at + 12);
    file.writeUInt32LE(SECTION_SIZE, at + 16);
    file.writeUInt32LE(offset, at + 20);
    file.writeUInt32LE(flags, at + 36);
  });
  Buffer.from([
    0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x05,
    0xe8, 0xef, 0x00, 0x00, 0x00, 0xc3,
  ]).copy(file, PE_IMAGE.textOffset);
  Buffer.from([0x31, 0xc0, 0xc3]).copy(file, PE_IMAGE.textOffset + 0x100);
  file.writeBigUInt64LE(0xdeadbeefn, PE_IMAGE.dataOffset);
  return file;
};

/** A Cheat Engine 7.5 table aimed at the image above. */
export const createCheatTable =
  (): string => `<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="45">
  <CheatEntries>
    <CheatEntry>
      <ID>0</ID>
      <Description>"Player"</Description>
      <Options moHideChildren="1"/>
      <GroupHeader>1</GroupHeader>
      <CheatEntries>
        <CheatEntry>
          <ID>1</ID>
          <Description>"Health"</Description>
          <VariableType>Float</VariableType>
          <Address>"game.exe"+2000</Address>
          <Offsets>
            <Offset>10</Offset>
            <Offset>B8</Offset>
          </Offsets>
          <Hotkeys>
            <Hotkey><Action>Set Value</Action><Keys><Key>112</Key></Keys><Value>100</Value><ID>0</ID></Hotkey>
          </Hotkeys>
        </CheatEntry>
      </CheatEntries>
    </CheatEntry>
    <CheatEntry>
      <ID>2</ID>
      <Description>"Infinite health &amp; ammo"</Description>
      <VariableType>Auto Assembler Script</VariableType>
      <AssemblerScript><![CDATA[[ENABLE]
aobscanmodule(health,game.exe,48 8B 05 ?? ?? ?? ?? 48 85 C0) // player pointer
aobscanmodule(other,other.dll,DE AD BE EF)
assert(game.exe+1000,48 8B 05 F9 0F 00 00)
assert(game.exe+1007,90 90)
alloc(newmem,$1000,health)
registersymbol(health)
[DISABLE]
unregistersymbol(health)
dealloc(newmem)
]]></AssemblerScript>
    </CheatEntry>
  </CheatEntries>
  <UserdefinedSymbols>
    <SymbolEntry><Name>playerBase</Name><Address>game.exe+2000</Address></SymbolEntry>
  </UserdefinedSymbols>
  <Structures StructVersion="2">
    <Structure Name="Player" AutoFill="0" AutoCreate="1" DefaultHex="0">
      <Elements>
        <Element Offset="16" Vartype="Float" Bytesize="4" OffsetHex="00000010" Description="health"/>
        <Element Offset="184" Vartype="Pointer" Bytesize="8" OffsetHex="000000B8" Description="stats"/>
      </Elements>
    </Structure>
  </Structures>
  <LuaScript>-- table script
print("hello")
</LuaScript>
</CheatTable>
`;
