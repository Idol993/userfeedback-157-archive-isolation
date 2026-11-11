import io, os, shutil, uuid
from . import catalog
from .extract import extract

def import_package(tenant,package,data,key):
    ident=str(uuid.uuid4())
    stage=catalog.root()/tenant/package/'staging'
    output=catalog.root()/tenant/package/ident
    try:
        names=extract(io.BytesIO(data),stage)
        stage.rename(output)
        if os.environ.get('IMPORT_FAILPOINT')=='after_publish': os._exit(77)
        catalog.publish(tenant,package,ident,output,key)
        if os.environ.get('IMPORT_FAILPOINT')=='after_commit': os._exit(77)
        return {'version':ident,'files':names,'state':'published'}
    except Exception:
        if stage.exists(): shutil.rmtree(stage)
        raise
