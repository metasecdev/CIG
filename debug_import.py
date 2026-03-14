import os
import traceback

out = []
try:
    import app
    out.append(f'app module: {app.__file__}')
    import app.main
    out.append(f'app.main module: {app.main.__file__}')
except Exception as e:
    out.append('ERROR: ' + str(e))
    out.append(traceback.format_exc())

with open('debug_import_out.txt', 'w') as f:
    f.write('\n'.join(out))
