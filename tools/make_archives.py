import io, zipfile
from pathlib import Path

def archive(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name,data in entries: bundle.writestr(name,data)
    return output.getvalue()
if __name__=='__main__':
    dest=Path('fixtures/generated'); dest.mkdir(parents=True,exist_ok=True)
    (dest/'normal.zip').write_bytes(archive([('assets/hello.txt','hello'),('empty.txt','')]))
    (dest/'parent.zip').write_bytes(archive([('../sentinel.txt','local fixture')]))
    print(dest.resolve())
