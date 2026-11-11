import zipfile
from pathlib import Path

def extract(archive,destination):
    destination=Path(destination); destination.mkdir(parents=True,exist_ok=True)
    names=[]
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            path=destination/entry.filename
            if entry.is_dir(): path.mkdir(parents=True,exist_ok=True); continue
            path.parent.mkdir(parents=True,exist_ok=True)
            with bundle.open(entry) as source, path.open('wb') as target: target.write(source.read())
            names.append(entry.filename)
    return names
