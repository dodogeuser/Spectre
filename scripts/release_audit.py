"""Local heuristic audit of release payload. Not a CVE audit or secret guarantee."""
import ast
import json
import re
from pathlib import Path
from scripts.release_package import files,ROOT


def scan(root=ROOT):
    findings=[]
    patterns=[('private-key',re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),('token-pattern',re.compile(r'\b(?:ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{30,})\b'))]
    for file in files(root):
        if not file.is_file():continue
        name=file.relative_to(root).as_posix()
        if name=='.env' or any(part in {'.local','.git','.venv','output','logs','tmp'} for part in file.relative_to(root).parts):findings.append({'severity':'HIGH','file':name,'issue':'private runtime file in release payload'})
        try:content=file.read_text(encoding='utf-8')
        except (UnicodeError,OSError):continue
        for label,pattern in patterns:
            if pattern.search(content):findings.append({'severity':'HIGH','file':name,'issue':label})
        if file.suffix=='.py':
            tree=ast.parse(content,filename=name)
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):findings.append({'severity':'HIGH','file':name,'issue':'shell=True'})
        for marker in ('TODO','FIXME'):
            if marker in content:findings.append({'severity':'INFORMATIONAL','file':name,'issue':marker})
    return findings


if __name__=='__main__':
    result=scan();print(json.dumps({'findings':result,'scope':'allowlisted release payload; heuristic only'},indent=2));raise SystemExit(int(any(f['severity']=='HIGH' for f in result)))
