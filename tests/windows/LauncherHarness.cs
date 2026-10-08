using System;
using System.Diagnostics;
using System.Collections.Generic;
using SpectreLauncher;
class Harness {
 static int Main(string[] args) {
  var owned=new List<Process>();
  try {
   if(args[1]=="error") {
    try {Engine.Launch(args[0],url=>{throw new Exception("Browser must not open on failure");},3,p=>owned.Add(p));return 2;}
    catch(Exception e){Console.WriteLine(e.Message);return 0;}
   }
   int opens=0;
   Action<string> browser=url=>{if(!Engine.Ready(url))throw new Exception("Browser before readiness");opens++;};
   string first=Engine.Launch(args[0],browser,20,p=>owned.Add(p));
   string second=Engine.Launch(args[0],browser,20,p=>owned.Add(p));
   if(owned.Count!=1||opens!=2||first!=second)throw new Exception("Duplicate launch/readiness regression");
   Console.WriteLine("READY_BEFORE_BROWSER; SINGLE_SERVER; REUSED; "+first);return 0;
  }catch(Exception e){Console.WriteLine(e.ToString());return 1;}
  finally {foreach(var p in owned)try{p.Kill();}catch{}}
 }
}
