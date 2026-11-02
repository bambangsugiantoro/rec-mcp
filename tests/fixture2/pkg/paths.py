import os
ROOT = "/srv/notes"
def note_path(name):
    return os.path.join(ROOT, name + ".txt")
