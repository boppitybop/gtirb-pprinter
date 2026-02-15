"""
Tests that symbol names resembling hex constants are properly renamed
to avoid assembly failures in Intel syntax.

In GAS Intel syntax, symbol names like "Bh", "FF", "AB", "0xBEEF"
look like hexadecimal numeric constants.  When such names appear in
bracket expressions (e.g. [RIP+FF+1]), GAS mis-parses them as numbers,
causing errors like:
    `QWORD PTR [RIP+FF+1]' is not a valid base/index expression

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
    """Create an IR with a function whose symbol has the given name."""
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    _, bi = add_text_section(m)
    cb = add_code_block(bi, b"\xc3")
    add_function(m, name, cb)

    return ir


class HexLabelNameIntelTest(PPrinterTest):
    """
    Test that symbols whose names look like hex constants are renamed
    in Intel syntax to avoid GAS mis-parsing them.
    """

    def test_hex_like_symbols_renamed_intel(self):
        """Hex-like names should be renamed in Intel syntax."""
        cases = ["Bh", "FF", "DEADh", "AB", "A", "0xBEEF", "0XA7"]
        for name in cases:
            with self.subTest(name=name):
                ir = create_ir_with_hex_symbol(name)
                asm = run_asm_pprinter(
                    ir, ["--syntax", "intel", "--format", "raw"]
                )
                self.assertIn(
                    f"{name}_renamed:", asm, f"{name!r} should be renamed"
                )

    def test_non_hex_not_renamed_intel(self):
        """Non-hex names must NOT be renamed."""
        cases = ["Gx", "hello"]
        for name in cases:
            with self.subTest(name=name):
                ir = create_ir_with_hex_symbol(name)
                asm = run_asm_pprinter(
                    ir, ["--syntax", "intel", "--format", "raw"]
                )
                self.assertIn(f"{name}:", asm)
                self.assertNotIn(f"{name}_renamed", asm)

    def test_hex_name_not_renamed_att(self):
        """
        In ATT syntax, hex-like names are NOT ambiguous (GAS doesn't
        use Intel-style hex), so they should NOT be renamed.
        """
        ir = create_ir_with_hex_symbol("CD")
        asm = run_asm_pprinter(ir, ["--syntax", "att"])
        self.assertIn("CD:", asm)
        self.assertNotIn("CD_renamed", asm)

    def test_hex_with_operand_reference(self):
        """
        Test that a hex-like symbol referenced in an operand (e.g. in a
        RIP-relative load) is also renamed in Intel syntax output.
        """
        ir, m = create_test_module(
            gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
        )

        # Data section with a target symbol named "EF"
        _, data_bi = add_data_section(m, 0x600000)
        db = add_data_block(data_bi, b"\x00" * 8)
        target_sym = add_symbol(m, "EF", db)

        # Code section: mov rax, qword ptr [rip+EF]
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
        self.assertIn("EF_renamed", asm)
        # The raw unrenamed name should not appear as a label
        self.assertNotIn("\nEF:", asm)


if __name__ == "__main__":
    unittest.main()
