import threading

class ThreadedXrefFinder(threading.Thread):
  def __init__(self, name, far_xrefs):
    self.name = name
    self.far_xrefs = far_xrefs
    self.lock = threading.Lock()
    threading.Thread.__init__(self)

  def run(self):
    xref_signatures = []
    for ea in self.far_xrefs:
      # Generate signature for xref
      signature = Signature.generate_unique_signature_for_ea(ea, True, False, ask_longer=False) 
      if signature.err is not None:
        continue

      # Update for statistics
      if len(signature) < shortest_length:
        shortest_length = len(signature)
        
      xref_signatures.append(signature)
      if len(xref_signatures) >= max_xrefs:
        break
    
    xref_signatures.sort(key = lambda x: len(x))
    if len(xref_signatures) > 0:
      xrefs[name] = xref_signatures[0]
    else:
      xrefs[name] = "No xrefs found"

  