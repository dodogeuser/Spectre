// Windows convenience launcher. Investigation code remains in the Python application.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Windows.Forms;

namespace SpectreLauncher {
 public static class Engine {
  static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 4096 };
  public static string ReadLocal(string url) {
   var request=(HttpWebRequest)WebRequest.Create(url);
   request.Proxy=null; request.AllowAutoRedirect=false; request.Timeout=800; request.ReadWriteTimeout=800;
   using(var response=(HttpWebResponse)request.GetResponse()) {
    if(response.StatusCode!=HttpStatusCode.OK || response.ContentLength>4096) throw new IOException();
    using(var reader=new StreamReader(response.GetResponseStream())) {
     char[] buffer=new char[4097];int count=reader.ReadBlock(buffer,0,buffer.Length);
     if(count>4096)throw new IOException();return new string(buffer,0,count);
    }
   }
  }
  public static bool Ready(string url) {
   try {
    var version=Json.Deserialize<Dictionary<string,object>>(ReadLocal(url+"version"));
    var health=Json.Deserialize<Dictionary<string,object>>(ReadLocal(url+"health"));
    return (string)version["version"]=="1.0.0" && (string)version["status"]=="release-candidate" && (string)health["status"]=="ok";
   } catch { return false; }
  }
  static ProcessStartInfo Python(string root,string python,string args) {
   var info=new ProcessStartInfo(python,args) { WorkingDirectory=root,UseShellExecute=false,CreateNoWindow=true };
   info.EnvironmentVariables.Remove("PYTHONPATH");info.EnvironmentVariables.Remove("PYTHONHOME");
   return info;
  }
  public static string Launch(string root,Action<string> browser,int timeoutSeconds=45,Action<Process> onStarted=null) {
   root=Path.GetFullPath(root);
   foreach(var name in new[]{"app\\run.py","app\\main.py","app\\config.py","app\\static\\index.html","launcher\\runtime_probe.py",".env"})
    if(!File.Exists(Path.Combine(root,name)))throw new Exception("Required file missing: "+name+". Extract the complete SPECTRE package and complete INSTALL_WINDOWS.md.");
   var python=Path.Combine(root,".venv","Scripts","python.exe");
   if(!File.Exists(python))throw new Exception("SPECTRE Python environment missing. Run scripts\\install_windows.ps1, configure .env, then retry.");
   var probeInfo=Python(root,python,"-m launcher.runtime_probe");probeInfo.RedirectStandardOutput=true;probeInfo.RedirectStandardError=true;
   string config;
   using(var probe=Process.Start(probeInfo)) {
    var output=probe.StandardOutput.ReadToEndAsync();var error=probe.StandardError.ReadToEndAsync();
    if(!probe.WaitForExit(15000)){probe.Kill();throw new Exception("Python/configuration check timed out. Run .venv\\Scripts\\python.exe -m app.doctor.");}
    if(probe.ExitCode!=0)throw new Exception("Python/configuration check failed. Check .env, installed requirements and loopback bind settings; run python -m app.doctor. Configuration values are withheld.");
    config=output.Result;
   }
   var values=Json.Deserialize<Dictionary<string,object>>(config);
   string host=(string)values["host"];int port=Convert.ToInt32(values["port"]);
   if((host!="127.0.0.1"&&host!="::1")||port<1||port>65535)throw new Exception("Launcher requires a safe loopback host and port.");
   string url="http://"+(host=="::1"?"[::1]":host)+":"+port+"/";
   using(var gate=new Mutex(false,"Local\\SPECTRE.Launcher."+port)) {
    bool locked=false;
    try {
     try {locked=gate.WaitOne(TimeSpan.FromSeconds(timeoutSeconds+20));}catch(AbandonedMutexException){locked=true;}
     if(!locked)throw new Exception("Another SPECTRE launch is in progress. Wait and retry.");
     if(Ready(url)){browser(url);return url;}
     using(var socket=new TcpClient(host=="::1"?AddressFamily.InterNetworkV6:AddressFamily.InterNetwork)) {
      try {socket.Connect(host,port);}catch(SocketException){}
      if(socket.Connected)throw new Exception("The configured local port is occupied by an unrecognized or unready service. No duplicate server started. Check the existing service or change SPECTRE_BIND_PORT.");
     }
     var start=Python(root,python,"-m app.run");
     start.EnvironmentVariables["SPECTRE_BIND_HOST"]=host;start.EnvironmentVariables["SPECTRE_BIND_PORT"]=port.ToString();
     using(var server=Process.Start(start)) {
      if(onStarted!=null)onStarted(server);
      var watch=Stopwatch.StartNew();
      while(watch.Elapsed.TotalSeconds<timeoutSeconds) {
       if(server.HasExited)throw new Exception("SPECTRE exited during startup (code "+server.ExitCode+"). Run python -m app.doctor, then python -m app.run for diagnostics.");
       if(Ready(url)){browser(url);return url;}
       Thread.Sleep(250);
      }
      // Do not terminate an application that may already have accepted work.
      throw new Exception("SPECTRE did not become ready within "+timeoutSeconds+" seconds. The server may still be starting; retry before starting it manually. Run python -m app.doctor for diagnostics.");
     }
    }finally {if(locked)gate.ReleaseMutex();}
   }
  }
 }
 public static class Program {
  [STAThread] public static int Main() {
   Application.EnableVisualStyles();
   try {
    Engine.Launch(AppDomain.CurrentDomain.BaseDirectory,url=>Process.Start(new ProcessStartInfo(url){UseShellExecute=true}));return 0;
   }catch(Exception error) {
    // Known validation errors are actionable; unexpected details are withheld.
    string message=error.GetType()==typeof(Exception)?error.Message:"Launcher could not start SPECTRE. Check installation permissions and run python -m app.doctor.";
    MessageBox.Show(message,"SPECTRE — Startup unavailable",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;
   }
  }
 }
}
