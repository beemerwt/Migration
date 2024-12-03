
# An idapython plugin that finds the signature of all named functions
# in the current IDB and writes them to a file, which can be applied
# to another IDB to rename functions.

# Arguments are 
# -o <output_file> : the file to write the signatures to when extracting them from an IDB
# -i <input_file> : the file to read the signatures from when applying them to an IDB

import idaapi
import idautils
import ida_funcs
import ida_name
import ida_kernwin
import json
import ida_xref

def check_sigmaker():
  builtins = __builtins__.__dict__
  is_installed = "generate_xref_signature" in builtins \
    and "generate_unique_signature" in builtins \
    and "is_signature_unique" in builtins \
    and "search_signature" in builtins
  if not is_installed:
    raise Exception("Signature Maker not installed")


def get_public():
  public_names = []
  public_funcs = []

  for (ea, name) in idautils.Names():
    if ida_name.is_public_name(ea):
      if ida_funcs.get_func(ea):
        public_funcs.append((name, ea))
      else:
        public_names.append((name, ea))

  return public_names, public_funcs


def get_name_signatures(public_names):
  signatures = dict()
  errored_signatures = dict()

  # iterate over all public names to find xref signatures
  for (name, ea) in public_names:
    try:
      namesig = generate_xref_signature(ea)
      signatures[name] = {
        "signature": namesig,
        "method": "xref"
      }
    except Exception as err:
      print("Failed to find signature for name %s at %x: %s" % (name, ea, str(err)))
      errored_signatures[name] = {
        "error": str(err),
        "ea": ea,
        "method": "xref"
      }

  return signatures, errored_signatures


def get_func_signatures(public_funcs):
  # create a map for names and public funcs
  signatures = dict()
  errored_signatures = dict()

  # iterate over all public functions
  for (name, ea) in public_funcs:
    try:
      funcsig = generate_unique_signature(ea)
      signatures[name] = {
        "signature": funcsig,
        "method": "unique"
      }
    except Exception as unique_err:
      print("Failed to find unique signature for function %s at %x: %s" % (name, ea, str(unique_err)))
      try:
        funcsig = generate_xref_signature(ea)
        signatures[name] = {
          "signature": funcsig,
          "method": "xref"
        }
      except Exception as xref_err:
        print("Failed to find xref signature for function %s at %x: %s" % (name, ea, str(xref_err)))
        errored_signatures[name] = {
          "ea": hex(ea),
          "xref_err": str(xref_err),
          "unique_err": str(unique_err)
        }

  return signatures, errored_signatures


def extract_signatures(output_file):
  check_sigmaker()
  public_names, public_funcs = get_public()

  func_signatures, errored_func_signatures = get_func_signatures(public_funcs)
  name_signatures, errored_name_signatures = get_name_signatures(public_names)

  signatures = dict()
  signatures['names'] = name_signatures
  signatures['functions'] = func_signatures

  errored_signatures = dict()
  errored_signatures['names'] = errored_name_signatures
  errored_signatures['functions'] = errored_func_signatures

  # Write the signatures to a file
  with open(output_file + ".json", "w") as f:
    json.dump(signatures, f)

  with open(output_file + "_errored.json", "w") as f:
    json.dump(errored_signatures, f)


# Checks input_file for missing names and functions in the current IDB
# Also checks for uniqueness of all signatures
def check_signatures(input_file, signatures = dict()):
  check_sigmaker()
  with open(input_file + ".json", "r") as f:
    filestr = f.read()
    signatures.update(json.loads(filestr))

  public_names, public_funcs = get_public()
  name_signatures = signatures['names']
  func_signatures = signatures['functions']

  check = {
    'missing_names': [],
    'missing_funcs': [],
    'common_names': [],
    'common_funcs': []
  }

  for (name, ea) in public_names:
    if name not in name_signatures:
      print("Missing name: %s" % name)
      check['missing_names'].append((name, ea))
    elif not is_signature_unique(name_signatures[name]['signature']):
      print("Signature no longer unique for name: %s" % name)
      check['common_names'].append((name, ea))

  for (name, ea) in public_funcs:
    if name not in func_signatures:
      print("Missing function: %s" % name)
      check['missing_funcs'].append((name, ea))
    elif not is_signature_unique(func_signatures[name]['signature']):
      print("Signature no longer unique for function: %s" % name)
      check['common_funcs'].append((name, ea))
  
  return check


def update_signatures(input_file):
  check_sigmaker()
  signatures = dict()
  errored_signatures = dict()
  check = check_signatures(input_file, signatures)
  with open(input_file + "_errored.json", "r") as f:
    filestr = f.read()
    errored_signatures.update(json.loads(filestr))

  name_signatures = signatures['names']
  func_signatures = signatures['functions']

  if len(check['missing_names']) > 0:
    print("Found %d missing names" % len(check['missing_names']))
    newsigs, errored = get_name_signatures(check['missing_names'])

    # update changed names
    for newname in newsigs:
      sig = newsigs[newname]['signature']
      for name in name_signatures:
        if name_signatures[name]['signature'] == sig:
          name_signatures[newname] = newsigs[newname]
          del name_signatures[name]

    name_signatures.update(newsigs)
    errored_signatures['names'].update(errored)

  # Update the signatures in the file
  if len(check['missing_funcs']) > 0:
    print("Found %d missing functions" % len(check['missing_funcs']))
    newsigs, errored = get_func_signatures(check['missing_funcs'])

    # update changed names
    for newname in newsigs:
      sig = newsigs[newname]['signature']
      for name in func_signatures:
        if func_signatures[name]['signature'] == sig:
          func_signatures[newname] = newsigs[newname]
          del func_signatures[name]

    func_signatures.update(newsigs)
    errored_signatures['functions'].update(errored)

  public_names, public_funcs = get_public()

  # Find new signatures for the common names and update them
  common_names = [ (name, ea) for (name, ea) in public_names if name in check['common_names'] ]
  common_sigs, common_errored = get_name_signatures(common_names)

  for name in common_errored:
    if name in name_signatures:
      del name_signatures[name]

  name_signatures.update(common_sigs)
  errored_signatures['names'].update(common_errored)

  # Find new signatures for the common functions and update them
  common_funcs = [ (name, ea) for (name, ea) in public_funcs if name in check['common_funcs'] ]
  common_sigs, common_errored = get_func_signatures(common_funcs)

  for name in common_errored:
    if name in func_signatures:
      del func_signatures[name]

  func_signatures.update(common_sigs)
  errored_signatures['functions'].update(common_errored)

  # Remove errored signatures that have been updated
  for name in func_signatures:
    if name in errored_signatures['functions']:
      del errored_signatures['functions'][name]

  for name in name_signatures:
    if name in errored_signatures['names']:
      del errored_signatures['names'][name]

  # Write the updated signatures to a file
  with open(input_file + ".json", "w") as f:
    json.dump(signatures, f)

  with open(input_file + "_errored.json", "w") as f:
    json.dump(errored_signatures, f)


def apply_xref_signature(name, signature):
  possible_eas = search_signature(signature)
  if len(possible_eas) == 0:
    raise Exception("No xref found for signature")
  
  if len(possible_eas) == 1:
    ea = possible_eas[0]
    if ea != idaapi.BADADDR:

      # Delete name
      if ida_name.get_name(ea) == name:
        print("Name at %x is already %s. Resetting." % (ea, name))
        ida_name.make_name_non_public(ea)
        ida_name.set_name(ea, "")

      var = ida_xref.get_first_dref_from(ea)
      if var != idaapi.BADADDR:
        print("Setting name %s at %x" % (name, var))
        ida_name.set_name(var, name)
        ida_name.make_name_public(var)
  else:
    print("Multiple xrefs found for signature %s" % signature)
    for ea in possible_eas:
      print("Function at %x" % ea)


def apply_signatures(input_file):
  check_sigmaker()
  # Read the signatures from a file
  print("Applying signatures from %s" % (input_file + ".json") )
  signatures = None
  with open(input_file + ".json", "r") as f:
    filestr = f.read()
    signatures = json.loads(filestr)
  
  name_signatures = signatures['names']
  func_signatures = signatures['functions']
  
  for name in name_signatures:
    signature = name_signatures[name]['signature']
    # all names are xref so we don't need to check method
    try:
      apply_xref_signature(name, signature)
    except Exception as err:
      print("Failed to apply signature for name %s: %s" % (name, str(err)))


  for name in func_signatures:
    signature = func_signatures[name]['signature']
    method = func_signatures[name]['method']

    if method == "unique":
      try:
        possible_eas = search_signature(signature)
        if len(possible_eas) == 0:
          raise Exception("No function found for signature")
        
        if len(possible_eas) == 1:
          ea = possible_eas[0]
          if ea != idaapi.BADADDR:
            ida_name.set_name(ea, name)
            ida_name.make_name_public(ea)
        else:
          print("Multiple functions found for signature %s" % signature)
          for ea in possible_eas:
            print("Function at %x" % ea)

      except Exception as err:
        print("Failed to apply signature for function %s: %s" % (name, str(err)))

    elif method == "xref":
      try:
        apply_xref_signature(name, signature)
      except Exception as err:
        print("Failed to apply signature for function %s: %s" % (name, str(err)))


if __name__ == "main":
  # get args
  import argparse
  parser = argparse.ArgumentParser(description='Extract function signatures from an IDB')
  parser.add_argument('-o', '--output', help='Output file to write signatures to')
  parser.add_argument('-i', '--input', help='Input file to read signatures from')
  args = parser.parse_args()

  if args.output:
    extract_signatures(args.output)
  elif args.input:
    apply_signatures(args.input)