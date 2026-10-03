using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;

class Peer {
 public string local_ip,remote_ip,protocol;
 public int local_port,remote_port;
 public long tx_bytes,rx_bytes;
}
class Program {
 static readonly object Gate=new object();
 static Dictionary<string,Peer> peers=new Dictionary<string,Peer>();
 static bool truncated;static DateTime started=DateTime.UtcNow;static JavaScriptSerializer json=new JavaScriptSerializer();
 static void Add(string src,int sport,string dst,int dport,int size,string protocol,bool sending) {
  if(size<0)return;
  string local=sending?src:dst,remote=sending?dst:src;int lp=sending?sport:dport,rp=sending?dport:sport;
  string key=local+"|"+lp+"|"+remote+"|"+rp+"|"+protocol;
  lock(Gate){Peer p;if(!peers.TryGetValue(key,out p)){if(peers.Count>=2000){truncated=true;return;}p=new Peer{local_ip=local,remote_ip=remote,local_port=lp,remote_port=rp,protocol=protocol};peers[key]=p;}if(sending)p.tx_bytes+=size;else p.rx_bytes+=size;}
 }
 static object Drain(long lost) {
  lock(Gate){var end=DateTime.UtcNow;var value=new{window_id=Guid.NewGuid().ToString(),started_at=started.ToString("o"),ended_at=end.ToString("o"),lost_events=lost,truncated=truncated||peers.Count>300,flows=peers.Values.OrderByDescending(x=>x.tx_bytes+x.rx_bytes).Take(300).ToArray()};peers=new Dictionary<string,Peer>();truncated=false;started=end;return value;}
 }
 static void Atomic(string path,string text){File.WriteAllText(path+".tmp",text,new System.Text.UTF8Encoding(false));if(File.Exists(path))File.Delete(path);File.Move(path+".tmp",path);}
 static int Main(string[] args) {
  if(args.Length==1&&args[0]=="--self-test"){
   Add("10.0.0.1",443,"10.0.0.2",52000,100,"TCP",true);Add("10.0.0.2",52000,"10.0.0.1",443,200,"TCP",false);
   var p=peers.Values.Single();if(p.tx_bytes!=100||p.rx_bytes!=200||p.local_port!=443||p.remote_ip!="10.0.0.2")return 2;
   Console.WriteLine("PASS: directional flow aggregation; no live capture performed");return 0;
  }
  if(args.Length!=1)return 2;string root=Path.GetFullPath(args[0]),lease=Path.Combine(root,"flow-approval.lease"),outdir=Path.Combine(root,"flow-windows");
  if(!File.Exists(lease)||(DateTime.UtcNow-File.GetLastWriteTimeUtc(lease)).TotalSeconds>150)return 3;
  Directory.CreateDirectory(outdir);
  using(var mutex=new Mutex(false,"Global\\NetCheckerFlowCollector")){
   try{if(!mutex.WaitOne(0))return 0;}catch(AbandonedMutexException){}
   try{
    using(var session=new TraceEventSession("NetChecker-Network-Observation")){
     session.StopOnDispose=true;
     var kernel=session.Source.Kernel;
     kernel.TcpIpSend+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"TCP",true);
     kernel.TcpIpRecv+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"TCP",false);
     kernel.TcpIpSendIPV6+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"TCP",true);
     kernel.TcpIpRecvIPV6+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"TCP",false);
     kernel.UdpIpSend+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"UDP",true);
     kernel.UdpIpRecv+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"UDP",false);
     kernel.UdpIpSendIPV6+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"UDP",true);
     kernel.UdpIpRecvIPV6+=e=>Add(e.saddr.ToString(),e.sport,e.daddr.ToString(),e.dport,e.size,"UDP",false);
     session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
     Atomic(Path.Combine(root,"flow-status.json"),json.Serialize(new{status="running",updated_at=DateTime.UtcNow.ToString("o")}));
     var watchdog=new Thread(()=>{
      try{while(true){Thread.Sleep(5000);if(!File.Exists(lease)||(DateTime.UtcNow-File.GetLastWriteTimeUtc(lease)).TotalSeconds>150){session.Dispose();break;}
       if((DateTime.UtcNow-started).TotalSeconds>=60){long lost=-1;var property=session.GetType().GetProperty("EventsLost");if(property!=null)lost=Convert.ToInt64(property.GetValue(session,null));
        Atomic(Path.Combine(outdir,DateTime.UtcNow.Ticks+".json"),json.Serialize(Drain(lost)));
        foreach(var old in new DirectoryInfo(outdir).GetFiles("*.json").OrderByDescending(f=>f.Name).Skip(5))old.Delete();
        Atomic(Path.Combine(root,"flow-status.json"),json.Serialize(new{status="running",updated_at=DateTime.UtcNow.ToString("o")}));
       }}
      }catch{session.Dispose();}
     });watchdog.IsBackground=true;watchdog.Start();session.Source.Process();
    }
    return 0;
   }catch(Exception e){Atomic(Path.Combine(root,"flow-status.json"),json.Serialize(new{status="unavailable",reason=e.GetType().Name,updated_at=DateTime.UtcNow.ToString("o")}));return 1;}
   finally{mutex.ReleaseMutex();}
  }
 }
}
