import ida_ua
import ida_idaapi
import ida_kernwin
import ida_bytes

ida_idaapi.require("Signature")
ida_idaapi.require("Main")


def test_sigmaker_name():
  ea = ida_kernwin.get_screen_ea()
  try:
    signature = generate_xref_signature(ea)
  except Exception as e:
    print(str(e))
    return


def test_sigmaker_sig():
  ea = ida_kernwin.get_screen_ea()
  try:
    signature = generate_unique_signature(ea)
  except Exception as e:
    print(str(e))
    return


def test_name():
  ea = ida_kernwin.get_screen_ea()
  try:
    name_sigs = Signature.find_xrefs(ea)
    if len(name_sigs) == 0:
      raise Exception("No xrefs found")
    
    print("Found %d xrefs" % len(name_sigs))
    print("Top 5 shortest xrefs:")
    for i in range(min(len(name_sigs), 5)):
      print(str(name_sigs[i]))

  except Exception as e:
    print(str(e))
    return