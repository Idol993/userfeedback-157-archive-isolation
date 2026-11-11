from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import FileResponse
from . import catalog, service

app=FastAPI(title='Tenant Package Import')
@app.post('/tenants/{tenant}/packages/{package}/imports',status_code=201)
async def upload(tenant:str,package:str,request:Request,idempotency_key:str='',x_tenant:str=Header(...)):
    if x_tenant!=tenant: raise HTTPException(403,'tenant mismatch')
    try: return service.import_package(tenant,package,await request.body(),idempotency_key)
    except Exception as exc: raise HTTPException(400,str(exc))
@app.get('/tenants/{tenant}/packages/{package}')
def get_package(tenant:str,package:str,x_tenant:str=Header(...)):
    row=catalog.latest(tenant,package)
    if not row: raise HTTPException(404,'package not found')
    return row
@app.get('/tenants/{tenant}/packages/{package}/files/{filename:path}')
def download(tenant:str,package:str,filename:str,x_tenant:str=Header(...)):
    from pathlib import Path
    row=catalog.latest(tenant,package)
    if not row: raise HTTPException(404,'package not found')
    path=Path(row['path'])/filename
    if not path.is_file(): raise HTTPException(404,'file not found')
    return FileResponse(path)
