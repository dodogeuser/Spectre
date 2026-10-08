"""Rebuild the GUI EXE using Windows' installed .NET Framework compiler."""
import os
from pathlib import Path
import subprocess


def main():
    root=Path(__file__).resolve().parents[1]
    compiler=Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if not compiler.is_file():raise SystemExit('Windows .NET Framework 4.x compiler unavailable.')
    subprocess.run([str(compiler),'/nologo','/target:winexe','/optimize+','/platform:anycpu',
                    '/reference:System.Windows.Forms.dll','/reference:System.Web.Extensions.dll',
                    '/win32icon:'+str(root/'app/static/images/branding/favicon.ico'),
                    '/out:'+str(root/'SPECTRE.exe'),str(root/'launcher/SpectreLauncher.cs')],check=True)
    print('Built SPECTRE.exe')


if __name__=='__main__':main()
