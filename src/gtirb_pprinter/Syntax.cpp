//===- Syntax.cpp -----------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2018 GrammaTech, Inc.
//
//  This code is licensed under the MIT license. See the LICENSE file in the
//  project root for license terms.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "Syntax.hpp"

#include "StringUtils.hpp"

#include <algorithm>
#include <boost/algorithm/string/replace.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <cctype>
#include <unordered_set>

namespace gtirb_pprint {

std::optional<std::string> Syntax::getSizeName(uint64_t bits) const {
  switch (bits) {
  case 256:
    return "YMMWORD";
  case 128:
    return "XMMWORD";
  case 80:
    return "TBYTE";
  case 64:
    return "QWORD";
  case 32:
    return "DWORD";
  case 16:
    return "WORD";
  case 8:
    return "BYTE";
  }
  return std::nullopt;
}

std::string Syntax::formatSectionName(const std::string& Name) const {
  return Name;
}

std::string Syntax::formatFunctionName(const std::string& Name) const {
  return Name;
}

std::string Syntax::formatSymbolName(const std::string& Name) const {
  return Name;
}

// Returns true if Name looks like it could be a hex literal (e.g. "AB",
// "DEADh", "0xBEEF").  GAS in Intel syntax will try to parse these as
// numbers rather than symbol references.
static bool looksLikeHexConstant(const std::string& Name) {
  if (Name.empty())
    return false;

  size_t Start = 0;
  size_t End = Name.size();

  // 0x / 0X prefix
  if (End > 2 && Name[0] == '0' && (Name[1] == 'x' || Name[1] == 'X')) {
    Start = 2;
  }
  // Trailing h / H suffix (only when there was no 0x prefix)
  else if (End > 1 && (Name.back() == 'h' || Name.back() == 'H')) {
    End = End - 1;
  }

  if (Start >= End)
    return false;

  return std::all_of(Name.begin() + Start, Name.begin() + End,
                     [](unsigned char C) { return std::isxdigit(C); });
}

std::string Syntax::sanitizeSymbolName(const std::string& Name) const {
  // x86 register names and assembler keywords that GAS would interpret
  // as something other than a symbol reference in Intel syntax.
  // Stored lowercase; lookup is case-insensitive via ascii_str_tolower.
  static const std::unordered_set<std::string> Reserved{
      // 8-bit GP registers
      "al",
      "ah",
      "bl",
      "bh",
      "cl",
      "ch",
      "dl",
      "dh",
      "spl",
      "bpl",
      "sil",
      "dil",
      "r8b",
      "r9b",
      "r10b",
      "r11b",
      "r12b",
      "r13b",
      "r14b",
      "r15b",
      // 16-bit GP registers
      "ax",
      "bx",
      "cx",
      "dx",
      "sp",
      "bp",
      "si",
      "di",
      "r8w",
      "r9w",
      "r10w",
      "r11w",
      "r12w",
      "r13w",
      "r14w",
      "r15w",
      // 32-bit GP registers
      "eax",
      "ebx",
      "ecx",
      "edx",
      "esp",
      "ebp",
      "esi",
      "edi",
      "r8d",
      "r9d",
      "r10d",
      "r11d",
      "r12d",
      "r13d",
      "r14d",
      "r15d",
      // 64-bit GP registers
      "rax",
      "rbx",
      "rcx",
      "rdx",
      "rsp",
      "rbp",
      "rsi",
      "rdi",
      "r8",
      "r9",
      "r10",
      "r11",
      "r12",
      "r13",
      "r14",
      "r15",
      "rip",
      // Segment registers / assembler keywords
      "fs",
      "ss",
      "mod",
      "not",
      "and",
      "or",
      "shr",
  };

  if (Reserved.count(ascii_str_tolower(Name))) {
    return Name + "_renamed";
  }

  // Names like "Bh" or "FF" get parsed as hex literals by GAS in Intel mode.
  if (looksLikeHexConstant(Name)) {
    return Name + "_renamed";
  }

  return Name;
}

std::string Syntax::escapeByte(uint8_t b) const {
  switch (b) {
  case '\\':
    return std::string("\\\\");
  case '\"':
    return std::string("\\\"");
  case '\n':
    return std::string("\\n");
  case '\t':
    return std::string("\\t");
  case '\b':
    return std::string("\\b");
  case '\f':
    return std::string("\\f");
  case '\r':
    return std::string("\\r");
  case '\a':
    return std::string("\\a");
  default:
    return std::string(1, b);
  }
}

} // namespace gtirb_pprint
