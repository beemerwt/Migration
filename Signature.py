import threading
import idc
import idautils
import ida_range
import ida_xref
import ida_funcs
import ida_bytes
import ida_ida
import ida_ua
import ida_kernwin

Signature_IDA = 0
Signature_x64Dbg = 1
Signature_Mask = 2
SignatureByteArray_Bitmask = 3
USE_QIS_SIGNATURE = False

def BIT(x):
  return 1 << x

INVALID_FUNCTION_ADDRESS = "Invalid function address"
NOT_CODE = "Not code"
FAILED_FIRST_INSTRUCTION = "Failed to decode first instruction"
FAILED_TO_DECODE= "Failed to decode instruction" 
DONT_CONTINUE = "User chose not to continue"
TOO_LONG = "Signature too long"
ABORTED = "Aborted"
USER_CANCELLED = "User cancelled"
SIG_LEFT_SCOPE = "Signature left function scope"

# Double-checked and this is compatible with the same C++ code
WildcardableOperandTypeBitmask = BIT( idc.o_reg ) | BIT( idc.o_mem ) | BIT( idc.o_phrase ) \
  | BIT( idc.o_displ ) | BIT( idc.o_far ) | BIT( idc.o_near ) | BIT( idc.o_imm ) \
  | BIT( idc.o_idpspec0 ) | BIT( idc.o_idpspec1 ) | BIT( idc.o_idpspec2 ) \
  | BIT( idc.o_idpspec3 ) | BIT( idc.o_idpspec4 ) | BIT( idc.o_idpspec5 )


class SignatureByte:
  def __init__(self):
    self.value = 0
    self.is_wildcard = False


class InstructionOperandInfo:
  def __init__(self, offset = 0, length = 0):
    self.offset = offset
    self.length = length


class Iter_Impl:
  def __init__(self, _iter):
    self._iter = _iter
    self.index = 0
  
  def __iter__(self):
    self.index = 0
    return self
  
  def __next__(self) -> SignatureByte:
    if self.index < len(self._iter):
        value = self._iter[self.index]
        self.index += 1
        return value
    else:
        raise StopIteration


# Example signature: "DE AD BE EF 00"
class Signature:
  def __init__(self, ea, mask_="", type = Signature_IDA):
    self.ea = ea
    self.err = None
    self.signature = []
    self.sigtype = type
    self.unique = False

  def is_valid(self):
    return self.ea != idc.BADADDR

  def __iter__(self):
    return iter(Iter_Impl(self))

  def __len__(self):
    return len(self.signature)

  def __str__(self):
    # Cache sigstr
    if self.sigtype == Signature_IDA:
      return build_ida_sig_string(self)
    elif self.sigtype == Signature_x64Dbg:
      return build_ida_sig_string(self, True)
    elif self.sigtype == Signature_Mask:
      return build_byte_array_with_mask_sig_string(self)
    elif self.sigtype == SignatureByteArray_Bitmask:
      return build_bytes_with_bitmask_sig_string(self)

    return ""

  def __getitem__(self, index):
    return self.signature[index]

  def __setitem__(self, index: int, value: SignatureByte):
    self.signature[index] = value

  def append(self, sigbyte: SignatureByte):
    self.signature.append(sigbyte)

  def is_unique(self):
    return self.unique


def build_ida_sig_string(signature: Signature, doubleQM=False):
  result = []

  # Build hex pattern
  for byte in signature:
    if byte.is_wildcard:
      result.append("??" if doubleQM else "?")
    else:
      result.append("{:02X}".format(byte.value))
  
  return " ".join(result)


def build_byte_array_with_mask_sig_string(signature: Signature):
  pattern = ""
  mask = ""
  # Build hex pattern
  for byte in signature:
    pattern += "\\x{:02X}".format(byte.value) if not byte.is_wildcard else 0
    mask += "x" if not byte.is_wildcard else "?"
  return pattern + " " + mask


def build_bytes_with_bitmask_sig_string(signature: Signature):
  pattern = ""
  mask = ""
  # Build hex pattern
  for byte in signature:
    pattern += "0x{:02X}, ".format(0 if byte.is_wildcard else byte.value)
    mask += "0" if byte.is_wildcard else "1"

  # Reverse bitmask
  mask = mask[::-1]

  # Remove separators
  pattern = pattern[:-2]
  return pattern + " " + " 0b" + mask


# Add tuple of the byte at the specified address and if it's a wildcard
def add_byte_to_sig(signature: Signature, address, wildcard):
  sigbyte = SignatureByte()
  sigbyte.value = ida_bytes.get_byte(address)
  sigbyte.is_wildcard = wildcard
  signature.append(sigbyte)


def add_bytes_to_sig(signature, address, count, wildcard):
  # signature.reserve( signature.size() + count ); // Not sure if this is overhead for average signature creation
  for i in range(count):
    add_byte_to_sig( signature, address + i, wildcard )


# Trim wildcards at end
def trim_sig(signature: Signature):
  i = next((i for i, byte in enumerate(reversed(signature)) \
            if not byte.is_wildcard), len(signature))
  signature.signature = signature.signature[:len(signature) - i]


def await_binsearch(start, end, binary_pattern, flags):
  result = ida_bytes.bin_search(start, end, binary_pattern, flags)
  while result[0] == idc.BADADDR:
    result = ida_bytes.bin_search(start, end, binary_pattern, flags)
  return result


def find_sig_occurrences(sigstr: str, skip_more_than_one = False):
  # if USE_QIS_SIGNATURE:
  #   return find_qis_sig_occurrences(signature, skip_more_than_one)
  
  binary_pattern = ida_bytes.compiled_binpat_vec_t()
  ida_bytes.parse_binpat_str(binary_pattern, ida_ida.inf_get_min_ea(), sigstr, 16)

  # Search for occurrences of the signature
  results = []
  ea = ida_ida.inf_get_min_ea()

  while True:
    occurrence = ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(), binary_pattern, ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD)
    if occurrence[0] == idc.BADADDR:
      break

    # In case we only care about uniqueness, return after more than one result
    if skip_more_than_one and len(results) > 1:
      break

    results.append(occurrence[0])
    ea = occurrence[0] + 1
  
  return results


def is_sig_unique(sigstr: str):
  return len(find_sig_occurrences(sigstr, True)) == 1


def get_operand_offset(instruction, op_info: InstructionOperandInfo, bitmask):
  op_info.offset = 0
  op_info.length = 0
  # Will not be handling ARM
  for op in instruction.ops:
    if op.type == idc.o_void: continue
    if op.offb == 0: continue
    if (BIT(op.type) & bitmask) == 0: continue

    op_info.offset = op.offb
    op_info.length = instruction.size - op.offb
    return True

  return False


def generate_unique_signature_for_ea(ea, wildcards = True, continue_outside = False, bitmask = WildcardableOperandTypeBitmask, max_length = 1000, ask_longer = True):
  signature = Signature(ea)
  if not signature.is_valid():
    signature.err = INVALID_FUNCTION_ADDRESS
    return signature
  
  if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
    signature.err = NOT_CODE
    return signature
  
  ida_kernwin.show_wait_box("Generating signature for 0x{:X}".format(ea))
  sig_part_length = 0
  current_func: ida_funcs.func_t = ida_funcs.get_func(ea)
  current_addr = ea
  try:
    while True:
      if ida_kernwin.user_cancelled():
        raise Exception(USER_CANCELLED)

      instruction = ida_ua.insn_t()
      current_length = ida_ua.decode_insn(instruction, current_addr)
      if current_length <= 0:
        if len(signature) == 0:
          raise Exception(FAILED_FIRST_INSTRUCTION)

        raise Exception(FAILED_TO_DECODE)
      
      # Length check in case the signature becomes too long
      if sig_part_length > max_length:
        if not ask_longer:
          raise Exception(TOO_LONG)

        # Ask user if they want to continue
        result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Signature is over {} bytes long. Continue?".format(max_length))
        if result == ida_kernwin.ASKBTN_YES:
          sig_part_length = 0
        elif result == ida_kernwin.ASKBTN_NO:
          raise Exception(DONT_CONTINUE)
        else:
          raise Exception(ABORTED)
      
      sig_part_length += current_length
      op_info = InstructionOperandInfo()
      if wildcards and get_operand_offset(instruction, op_info, bitmask) and op_info.length > 0:
        add_bytes_to_sig(signature, current_addr, op_info.offset, False)
        add_bytes_to_sig(signature, current_addr + op_info.offset, op_info.length, True)
        if op_info.offset == 0:
          add_bytes_to_sig(signature, current_addr + op_info.length, current_length - op_info.length, False)
      else:
        add_bytes_to_sig(signature, current_addr, current_length, False)
      
      sigstr = str(signature)
      if is_sig_unique(sigstr):
        trim_sig(signature)
        ida_kernwin.hide_wait_box()
        return signature
      
      current_addr += current_length
      if not continue_outside:
        if not current_func or not current_func.contains(current_addr):
          raise Exception(SIG_LEFT_SCOPE)

  except Exception as err:
    signature.err = str(err)
    ida_kernwin.hide_wait_box()
    return signature


def generate_sig_for_ea_range(ea_start, ea_end, wildcards, bitmask):
  signature = Signature(ea_start)
  signature.end_ea = ea_end

  if signature.is_valid():
    signature.err = INVALID_FUNCTION_ADDRESS
    return signature

  ida_kernwin.show_wait_box("Generating signature for range 0x{:X} - 0x{:X}".format(ea_start, ea_end))
  sig_part_length = 0

  try:
    # Copy data section, no wildcards
    if not ida_bytes.is_code(ida_bytes.get_flags(ea_start)):
      add_bytes_to_sig(signature, ea_start, ea_end - ea_start, False)
      raise Exception("Data section")
  
    current_addr = ea_start
    while True:
      if ida_kernwin.user_cancelled():
        raise Exception(USER_CANCELLED)
      
      instruction = ida_ua.insn_t()
      current_length = ida_ua.decode_insn(instruction, current_addr)
      if current_length <= 0:
        if len(signature) == 0:
          raise Exception(FAILED_FIRST_INSTRUCTION)
        
        print("Signature reached end of executable code at 0x{:X}".format(current_addr))
        if current_length < ea_end:
          add_bytes_to_sig(signature, current_addr, ea_end - current_addr, False)
        trim_sig(signature)
        raise Exception(SIG_LEFT_SCOPE)
      
      sig_part_length += current_length
      
      op_info = InstructionOperandInfo()
      if wildcards and get_operand_offset(instruction, op_info, bitmask) and op_info.length > 0:
        add_bytes_to_sig(signature, current_addr, op_info.offset, False)
        add_bytes_to_sig(signature, current_addr + op_info.offset, op_info.length, True)
        if op_info.offset == 0:
          add_bytes_to_sig(signature, current_addr + op_info.length, current_length - op_info.length, False)
      else:
        add_bytes_to_sig(signature, current_addr, current_length, False)

      current_addr += current_length
      if current_addr >= ea_end:
        trim_sig(signature)
        ida_kernwin.hide_wait_box()
        return signature
  except Exception as err:
    signature.err = str(err)
    ida_kernwin.hide_wait_box()
    return signature

NO_INITIAL_XREF = "No initial xref found"

def count_xrefs(ea, xref_type = ida_xref.XREF_FAR):
  count = 0
  for xref in idautils.XrefsTo(ea, xref_type):
    if ida_kernwin.user_cancelled():
      return count
    
    if ida_bytes.is_code(ida_bytes.get_flags(xref.frm)):
      count += 1
  
  return count


def get_far_xrefs(ea):
  xrefs = []
  for xref in idautils.XrefsTo(ea, ida_xref.XREF_FAR):  
    # Skip data refs, xref.iscode is not what we want though  
    if ida_bytes.is_code(ida_bytes.get_flags(xref.frm)):
      xrefs.append(xref.frm)
  
  return xrefs


# Returns a tuple (signature[], err)
def find_xrefs(ea, wildcards = True, continue_outside = False, max_length = 250, bitmask = WildcardableOperandTypeBitmask, max_xrefs=100):
  print("Finding xrefs for 0x{:X}".format(ea))
  xref_signatures = []
  err = None
  shortest_length = max_length + 1
  
  far_xrefs = get_far_xrefs(ea)

  for xref in far_xrefs:
    if ida_kernwin.user_cancelled():
      raise Exception(USER_CANCELLED)

    # Generate signature for xref
    signature = generate_unique_signature_for_ea(xref, wildcards, continue_outside, bitmask, max_length, False)
    if signature.err is not None:
      continue

    # Update for statistics
    if len(signature) < shortest_length:
      shortest_length = len(signature)

    xref_signatures.append(signature)
    if len(xref_signatures) >= max_xrefs:
      break

  # Sort signatures by length
  xref_signatures.sort(key = lambda x: len(x))
  return xref_signatures