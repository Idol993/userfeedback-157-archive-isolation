from importer import service,catalog
from tools.make_archives import archive
def test_normal_package(tmp_path,monkeypatch):
    monkeypatch.setenv('IMPORT_ROOT',str(tmp_path/'imports'))
    result=service.import_package('team-a','assets',archive([('data/hello.txt','hello')]),'k1')
    assert result['state']=='published'
    assert catalog.latest('team-a','assets')['id']==result['version']
