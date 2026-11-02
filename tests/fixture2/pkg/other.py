def note_path(name):
    return "/etc/" + name
def save(p, data):
    open(p, "w").write(data)
