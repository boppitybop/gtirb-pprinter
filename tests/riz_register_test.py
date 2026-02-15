"""
Tests that the RIZ/EIZ pseudo-registers are NOT emitted in assembly output.

RIZ/EIZ are pseudo-registers that represent "no index" in the x86 SIB byte
encoding.  Although capstone reports them as register operands, GAS does not
accept them as valid register names, causing assembly failures.

The pretty-printer must suppress RIZ/EIZ from the output.
"""

import unittest

import gtirb

from gtirb_helpers import add_code_block, add_text_section, create_test_module
from pprinter_helpers import run_asm_pprinter, PPrinterTest


class RizRegisterTest(PPrinterTest):
    def test_no_riz_in_intel_syntax(self):
        """
        An instruction whose SIB byte encodes index=4 (meaning 'no index')
        should NOT produce 'RIZ' in Intel syntax output.

        Encoding: 8B 04 25 00 00 00 00
          opcode: 8B /r  (MOV r32, r/m32)
          ModR/M: 04 = mod=00, reg=000(EAX), r/m=100(SIB follows)
          SIB:    25 = scale=00(1), index=100(none/RIZ), base=101(disp32)
          disp32: 00 00 00 00

        Capstone decodes this with mem.index = X86_REG_RIZ, but the
        assembler (GAS) does not accept RIZ as a register name.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)

        # mov eax, dword ptr [disp32]  -- SIB with no index (RIZ)
        add_code_block(bi, b"\x8b\x04\x25\x00\x00\x00\x00")

        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        # RIZ should never appear in the output
        self.assertNotIn("RIZ", asm)
        self.assertNotIn("riz", asm)
        # The instruction should still be present (as a mov)
        self.assertIn("mov", asm.lower())

    def test_no_riz_in_att_syntax(self):
        """
        Same instruction should not produce '%riz' in ATT syntax output.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.X64
        )
        _, bi = add_text_section(m)

        # mov eax, dword ptr [disp32]  -- SIB with no index (RIZ)
        add_code_block(bi, b"\x8b\x04\x25\x00\x00\x00\x00")

        asm = run_asm_pprinter(ir, ["--syntax=att"])
        # %riz should never appear
        self.assertNotIn("%riz", asm)
        self.assertNotIn("riz", asm.lower())

    def test_no_eiz_in_intel_ia32(self):
        """
        In 32-bit mode, the same SIB encoding produces EIZ instead of RIZ.
        Verify it is also suppressed.

        Encoding (IA32): 8B 04 25 00 00 00 00
          Same instruction in 32-bit mode uses EIZ.
        """
        ir, m = create_test_module(
            file_format=gtirb.Module.FileFormat.ELF, isa=gtirb.Module.ISA.IA32
        )
        _, bi = add_text_section(m)

        # mov eax, dword ptr [disp32]  -- SIB with no index (EIZ)
        add_code_block(bi, b"\x8b\x04\x25\x00\x00\x00\x00")

        asm = run_asm_pprinter(ir, ["--syntax=intel"])
        # EIZ should never appear in the output
        self.assertNotIn("EIZ", asm)
        self.assertNotIn("eiz", asm)


if __name__ == "__main__":
    unittest.main()
