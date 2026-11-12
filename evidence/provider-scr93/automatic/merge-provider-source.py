import fcntl,hashlib,json,os,subprocess
from pathlib import Path

source=Path('/home/devuser/Documents/Projects/scopeweaver')
isolated=Path('/home/devuser/Documents/Projects/scopeweaver-provider-scr93')
proof=isolated/'evidence/provider-scr93/automatic/source-merge-verification.json'
expected='84cf0779665d5e32b7fc6b41acb9d95b8493c77b'
base='75a706d3146f9537ebf2cabe00ca540b6b033a85'
allowed_dirty={'.gitignore','db/db.go','server/engine.go','skills/playwright-cli/SKILL.md','skills/scopesentry/SKILL.md'}
os.umask(0o077)
lock=open('/tmp/scopeweaver-provider-scr93/source-merge.lock','a')
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)

def git(*args):
 return subprocess.check_output(['git','-C',str(source),*args])
def text(*args):return git(*args).decode().strip()
def digest(data):return hashlib.sha256(data).hexdigest()
def runtime():
 # Select metadata at Docker's output boundary: never retrieve Config.Env or credentials.
 fmt='{{.Id}}|{{.Image}}|{{.State.Running}}|{{.State.StartedAt}}|{{.RestartCount}}'
 parts=subprocess.check_output(['docker','inspect','--format',fmt,'scopeweaver-scopeweaver-1'],text=True).strip().split('|')
 return dict(zip(['container_id','image_id','running','started_at','restart_count'],parts))
def existing_state():
 return {
  'unstaged_diff_sha256':digest(git('diff','--binary')),
  'staged_diff_sha256':digest(git('diff','--cached','--binary')),
  'untracked_listing_sha256':digest(git('ls-files','--others','--exclude-standard','-z')),
  'tracked_status_sha256':digest(git('status','--porcelain=v1','--untracked-files=no')),
 }
def save(record):
 temporary=proof.with_suffix('.tmp')
 temporary.write_text(json.dumps(record,indent=2)+'\n')
 temporary.replace(proof)

assert text('branch','--show-current')=='main','Target is not main; stopped'
assert text('rev-parse','feat/provider-scr93')==expected,'Reviewed branch changed; stopped'
assert text('rev-parse','HEAD')==base,'Main changed since review; stopped'
changed=set(text('diff','--name-only','main...feat/provider-scr93').splitlines())
dirty=set(text('diff','HEAD','--name-only').splitlines())
assert dirty==allowed_dirty,'Existing tracked edits changed since review; stopped'
assert not changed & dirty,'Source changes overlap existing edits; stopped'
untracked=set(git('ls-files','--others','--exclude-standard','-z').decode().split('\0'))
assert not changed & untracked,'Source update would collide with untracked files; stopped'
subprocess.run(['git','-C',str(source),'merge-base','--is-ancestor','main','feat/provider-scr93'],check=True,capture_output=True)
before=existing_state();running=runtime()
assert running['running']=='true','Existing service is not running; stopped'
mounts=subprocess.check_output(['docker','inspect','--format','{{range .Mounts}}{{printf "%s\\n" .Source}}{{end}}','scopeweaver-scopeweaver-1'],text=True).splitlines()
assert not any(Path(m)==source/p or Path(m) in (source/p).parents for m in mounts for p in changed),'Changed source files are mounted into the running service; stopped'
record={'state':'started','authorization':'captain chose Authorize VPS source update','source':str(source),'branch':'feat/provider-scr93','before_head':base,'reviewed_head':expected,'existing_edits_before':before,'runtime_before':running,'rebuild':False,'restart':False,'activation':False,'production_credentials_created':False}
save(record)
# A fast-forward creates no merge commit. Disable hooks for this one command so
# no repository hook can rebuild or deploy; do not change persistent Git config.
result=subprocess.run(['git','-C',str(source),'-c','core.hooksPath=/dev/null','-c','merge.autoStash=false','merge','--ff-only','feat/provider-scr93'],capture_output=True)
record['merge_returncode']=result.returncode
record['after_head']=text('rev-parse','HEAD')
record['existing_edits_after']=existing_state()
record['runtime_after']=runtime()
record['existing_edits_preserved']=record['existing_edits_after']==before
record['running_service_unchanged']=record['runtime_after']==running
record['state']='succeeded' if result.returncode==0 and record['after_head']==expected and record['existing_edits_preserved'] and record['running_service_unchanged'] else 'needs-review'
save(record)
print('Source merge state:',record['state'])
print('ScopeWeaver main matches reviewed provider version:',record['after_head']==expected)
print('Existing tracked/staged edits and untracked listing preserved:',record['existing_edits_preserved'])
print('Deployed container, image, start time and restart count unchanged:',record['running_service_unchanged'])
print('Rebuild, restart, activation and production credentials: none')
if record['state']!='succeeded':raise SystemExit(1)
