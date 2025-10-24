import hashlib, os

def hash_integrity(path):
    if not os.path.exists(path): 
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()
