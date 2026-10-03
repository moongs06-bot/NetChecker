using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;

[assembly: AssemblyTitle("NetChecker AI Agent 디펜더")]
[assembly: AssemblyDescription("Windows 서버 및 중요 PC 보안 점검 수집기")]
[assembly: AssemblyVersion("0.2.0.0")]
class Setup : Form {
 readonly Button install = new Button();
 readonly Label status = new Label();
 readonly ProgressBar progress = new ProgressBar();
 bool working;
 [STAThread] static void Main() {
  Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); Application.Run(new Setup());
 }
 Setup() {
  Text="NetChecker AI Agent 디펜더"; ClientSize=new Size(580,360); Font=new Font("맑은 고딕",10);
  StartPosition=FormStartPosition.CenterScreen; FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false; BackColor=Color.White;
  var title=new Label {Text="AI Agent 디펜더",Font=new Font("맑은 고딕",23,FontStyle.Bold),AutoSize=true,Location=new Point(28,24)};
  var info=new Label {Text="Windows 서버 · 중요 PC 공용 보안 점검 Agent\n\n로그인 실패 · 보안 이벤트 · Windows Defender 상태를 수집합니다.\n기존 NetChecker 등록 정보를 유지하며 신규 장비는 승인 후 수집합니다.\n관리자가 승인한 조치만 실행하며 적용 상태를 다시 확인합니다.",Location=new Point(30,85),Size=new Size(520,115)};
  status.SetBounds(30,210,520,55); status.Text="설치를 누르면 필요한 파일과 자동 실행 설정을 구성합니다.";
  progress.SetBounds(30,274,520,10); progress.Visible=false; progress.Style=ProgressBarStyle.Marquee;
  install.Text="설치"; install.SetBounds(420,303,130,38); install.BackColor=Color.FromArgb(35,91,234);install.ForeColor=Color.White;install.FlatStyle=FlatStyle.Flat;
  install.Click+=(s,e)=>Install(); Controls.AddRange(new Control[]{title,info,status,progress,install});
  FormClosing+=(s,e)=>{ if(working)e.Cancel=true; };
 }
 void Install() {
  if(install.Text=="닫기"){Close();return;}
  working=true;install.Enabled=false;progress.Visible=true;status.Text="설치 중입니다. 잠시 기다려 주세요.";
  var worker=new BackgroundWorker();
  worker.DoWork+=(s,e)=>RunInstaller();
  worker.RunWorkerCompleted+=(s,e)=>{
   working=false;progress.Visible=false;install.Enabled=true;
   if(e.Error!=null){status.Text="설치하지 못했습니다. 관리자에게 아래 오류를 알려 주세요.";MessageBox.Show(this,e.Error.Message,"설치 오류",MessageBoxButtons.OK,MessageBoxIcon.Error);install.Text="설치";}
   else {status.Text="설치 완료! 바탕화면의 AI Agent 디펜더를 실행하세요.\n신규 장비만 등록 대기 목록에서 승인해 주세요.";install.Text="닫기";}
  };worker.RunWorkerAsync();
 }
 static void RunInstaller() {
  string folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"NetCheckerSetup-"+Guid.NewGuid().ToString("N"));
  var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
  foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  Directory.CreateDirectory(folder,acl);
  string[] names={"Install-Defender.ps1","Collector-Defender.ps1","Uninstall-Defender.ps1","Install-NetChecker.ps1","Collector.ps1","Uninstall-NetChecker.ps1","Read-PortEvents.ps1","flow.zip","NetChecker-Defender.exe","Actions-Defender.ps1","Inventory-Defender.ps1","Scan-Defender.ps1"};
  try {
   foreach(string name in names)using(Stream input=Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) {
    if(input==null)throw new InvalidOperationException("설치 파일이 손상되었습니다.");
    using(var output=new FileStream(Path.Combine(folder,name),FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
   }
   string powershell=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32", "WindowsPowerShell", "v1.0", "powershell.exe");
   var start=new ProcessStartInfo(powershell,"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+Path.Combine(folder,names[0])+"\"");
   start.UseShellExecute=false;start.CreateNoWindow=true;start.WindowStyle=ProcessWindowStyle.Hidden;
   start.RedirectStandardOutput=true;start.RedirectStandardError=true;
   using(var process=new Process()){process.StartInfo=start;string error="";
    process.OutputDataReceived+=(s,e)=>{};process.ErrorDataReceived+=(s,e)=>{if(e.Data!=null&&error.Length<3000)error+=e.Data+Environment.NewLine;};
    process.Start();process.BeginOutputReadLine();process.BeginErrorReadLine();process.WaitForExit();
    if(process.ExitCode!=0)throw new InvalidOperationException("설치 작업 실패 ("+process.ExitCode+")\n"+error);
   }
  }finally{
   foreach(string name in names){try{File.Delete(Path.Combine(folder,name));}catch{}}
   try{Directory.Delete(folder,false);}catch{}
  }
 }
}
