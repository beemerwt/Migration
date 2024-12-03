# IDA Pro v9.x Migration Script
Ever been working on reversing an application that was recently patched? This is the solution. This plugin is able to save all public names and functions you've been working with to a json file to be applied to a patched application.

Just save this repo, open Ida 9, load the Main.py script and you can use any of these functions:

1. **extract_signatures(filename)** - writes all public names and functions within the current IDB to "filename.json" any errors will be written to "filename_errored.json"
2. **apply_signatures(filename)** - applies all saved public names and functions from "filename.json" to the IDB
3. **check_signatures(filename)** - lists all public names and functions that are not in "filename.json"
4. **update_signatures(filename)** - verifies all signatures in the file are unique, finds new ones if they aren't, and any new names/functions will be added


Uses my fork of the IdaSigMaker Repo: https://github.com/beemerwt/IDA-Pro-SigMaker