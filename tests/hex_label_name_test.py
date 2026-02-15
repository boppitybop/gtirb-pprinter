"""
Tests that symbol names resembling hex constants are properly renamed
to avoid assembly failures in Intel syntax.

In GAS Intel syntax, symbol names like "Cx", "Ax", "Bh", "FF", "AB"
look like hexadecimal numeric constants.  When such names appear in
bracket expressions (e.g. [RIP+Cx+1]), GAS mis-parses them as numbers,
causing errors like:
    `QWORD PTR [RIP+Cx+1]' is not a valid base/index expression

The pretty-printer renames these symbols by appending "_renamed".
"""

import unittest

import gtirb

from gtirb_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_text_section,
    add_symbol,
    add_function,
    create_test_module,
)
from pprinter_helpers import run_asm_pprinter, PPrinterTest


def create_ir_with_hex_symbol(name: str) -> gtirb.IR:
    """
    Create an IR with a function whose symbol has the given name, and a
    RIP-relative memory reference to a data symbol also with that name.
    This exercises both label definitions and operand references.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    # Create code section with a function
    _, bi = add_text_section(m)
    cb = add_code_block(bi, b"\xc3")
    add_function(m, name, cb)

    return ir


class HexLabelNameIntelTest(PPrinterTest):
    """
    Test that symbols whose names look like hex constants are renamed
    in Intel syntax to avoid GAS mis-parsing them.
    """

    def test_Cx_renamed_intel(self):
        """'Cx' looks like a hex constant; should be renamed."""
        ir = create_ir_with_hex_symbol("Cx")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("Cx_renamed:", asm)
        self.assertNotIn("\nCx:", asm)

    def test_Ax_renamed_intel(self):
        """'Ax' looks like a hex constant; should be renamed."""
        ir = create_ir_with_hex_symbol("Ax")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("Ax_renamed:", asm)

    def test_Bh_renamed_intel(self):
        """'Bh' ends with 'h' and could be parsed as 0Bh; should be renamed."""
        ir = create_ir_with_hex_symbol("Bh")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("Bh_renamed:", asm)

    def test_FF_renamed_intel(self):
        """'FF' is two hex digits; should be renamed."""
        ir = create_ir_with_hex_symbol("FF")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("FF_renamed:", asm)

    def test_DEADh_renamed_intel(self):
        """'DEADh' looks like hex constant 0xDEAD; should be renamed."""
        ir = create_ir_with_hex_symbol("DEADh")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("DEADh_renamed:", asm)

    def test_AB_renamed_intel(self):
        """'AB' is all hex digits; should be renamed."""
        ir = create_ir_with_hex_symbol("AB")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("AB_renamed:", asm)

    def test_non_hex_not_renamed_intel(self):
        """'Gx' is NOT hex (G is not a hex digit); must NOT rename."""
        ir = create_ir_with_hex_symbol("Gx")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("Gx:", asm)
        self.assertNotIn("Gx_renamed", asm)

    def test_hello_not_renamed_intel(self):
        """'hello' contains non-hex letters; must NOT be renamed."""
        ir = create_ir_with_hex_symbol("hello")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("hello:", asm)
        self.assertNotIn("hello_renamed", asm)

    def test_hex_name_not_renamed_att(self):
        """
        In ATT syntax, hex-like names are NOT ambiguous (GAS doesn't
        use Intel-style hex), so they should NOT be renamed.
        """
        ir = create_ir_with_hex_symbol("Cx")
        asm = run_asm_pprinter(ir, ["--syntax", "att"])
        # ATT syntax should keep the original name
        self.assertIn("Cx:", asm)
        self.assertNotIn("Cx_renamed", asm)

    def test_single_hex_digit_renamed_intel(self):
        """A single hex digit 'A' should be renamed in Intel syntax."""
        ir = create_ir_with_hex_symbol("A")
        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        self.assertIn("A_renamed:", asm)

    def test_hex_with_operand_reference(self):
        """
        Test that a hex-like symbol referenced in an operand (e.g. in a
        RIP-relative load) is also renamed in Intel syntax output.
        """
        ir, m = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
        )

        # Data section with a target symbol named "Cx"
        _, data_bi = add_data_section(m, 0x600000)
        db = add_data_block(data_bi, b"\x00" * 8)
        target_sym = add_symbol(m, "Cx", db)

        # Code section: mov rax, qword ptr [rip+Cx]
        # 48 8B 05 XX XX XX XX  ->  mov rax, [rip+disp32]
        _, text_bi = add_text_section(m, 0x400000)
        sym_expr = gtirb.SymAddrConst(0, target_sym)
        add_code_block(
            text_bi,
            b"\x48\x8b\x05\x00\x00\x00\x00",
            {3: sym_expr},
        )

        asm = run_asm_pprinter(ir, ["--syntax", "intel", "--format", "raw"])
        # The symbol should be renamed in both the label and the operand
        self.assertIn("Cx_renamed", asm)
        # The raw unrenamed name should not appear as a label
        self.assertNotIn("\nCx:", asm)


if __name__ == "__main__":
    unittest.main()
