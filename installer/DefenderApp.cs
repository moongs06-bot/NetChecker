using System;
using System.IO;
using System.Drawing;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Globalization;
[assembly:System.Reflection.AssemblyTitle("NetChecker AI Agent 디펜더")]
[assembly:System.Reflection.AssemblyVersion("0.3.0.0")]
class DefenderApp:Form {
 readonly Label headline=new Label(),detail=new Label(),time=new Label();
 readonly FlowLayoutPanel cards=new FlowLayoutPanel();
 readonly ListView events=new ListView(),actions=new ListView();
 readonly TextBox review=new TextBox(),scanStatus=new TextBox();
 readonly Timer timer=new Timer();
 readonly TabControl tabs=new TabControl();
 readonly NotifyIcon tray=new NotifyIcon();
 readonly JavaScriptSerializer json=new JavaScriptSerializer();
 string last="";bool quitting=false;readonly string statePath;
 [STAThread]static void Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);if(args.Length>=2&&args[0]=="/preview"){using(var f=new DefenderApp(args.Length>2?args[2]:null)){f.Opacity=0;f.ShowInTaskbar=false;f.Location=new Point(-2000,-2000);f.Show();if(args.Length>3)f.tabs.SelectedIndex=int.Parse(args[3]);Application.DoEvents();using(var b=new Bitmap(f.Width,f.Height)){f.DrawToBitmap(b,new Rectangle(0,0,f.Width,f.Height));b.Save(args[1],System.Drawing.Imaging.ImageFormat.Png);}f.quitting=true;f.Close();}return;}var app=new DefenderApp(null);if(args.Length>0&&args[0]=="/tray")app.Shown+=(s,e)=>app.Hide();Application.Run(app);}
 DefenderApp(string stateOverride){
  statePath=stateOverride??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"NetCheckerDefenderStatus","status.json");
  Text="NetChecker · AI Agent 디펜더";ClientSize=new Size(1030,730);MinimumSize=new Size(840,610);Font=new Font("맑은 고딕",10);BackColor=Color.FromArgb(244,247,247);StartPosition=FormStartPosition.CenterScreen;
  var header=new Panel{Dock=DockStyle.Top,Height=82,BackColor=Color.FromArgb(23,66,58)};
  var title=new Label{Text="NetChecker  AI Agent 디펜더",ForeColor=Color.White,Font=new Font("맑은 고딕",21,FontStyle.Bold),AutoSize=true,Location=new Point(25,15)};
  var sub=new Label{Text="보안 감지  ·  근거 검토  ·  승인 조치  ·  재검증",ForeColor=Color.FromArgb(192,222,212),AutoSize=true,Location=new Point(28,52)};header.Controls.AddRange(new Control[]{title,sub});Controls.Add(header);
  var footer=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=60,Padding=new Padding(18,10,18,10),BackColor=Color.White};
  var open=new Button{Text="관리자 대시보드",Width=175,Height=36};open.Click+=(s,e)=>Process.Start(new ProcessStartInfo("https://netchecker.example.com/netchecker/"){UseShellExecute=true});
  var refresh=new Button{Text="상태 새로고침",Width=155,Height=36};refresh.Click+=(s,e)=>RefreshState(true);
  var hide=new Button{Text="트레이로 접기",Width=145,Height=36};hide.Click+=(s,e)=>Hide();footer.Controls.AddRange(new Control[]{open,refresh,hide});Controls.Add(footer);
  var body=new Panel{Dock=DockStyle.Fill,Padding=new Padding(24,18,24,12)};Controls.Add(body);body.BringToFront();
  var summary=new Panel{Dock=DockStyle.Top,Height=110,BackColor=Color.White};
  headline.SetBounds(20,13,940,40);headline.Font=new Font("맑은 고딕",22,FontStyle.Bold);headline.Text="보안 수집 상태를 확인하고 있습니다";
  detail.SetBounds(22,58,940,22);detail.ForeColor=Color.FromArgb(83,102,96);
  time.SetBounds(22,82,940,21);time.Font=new Font("맑은 고딕",9);time.ForeColor=Color.Gray;summary.Controls.AddRange(new Control[]{headline,detail,time});body.Controls.Add(summary);
  cards.Dock=DockStyle.Top;cards.Height=105;cards.Padding=new Padding(0,14,0,8);cards.WrapContents=false;body.Controls.Add(cards);cards.BringToFront();summary.BringToFront();
  tabs.Dock=DockStyle.Fill;body.Controls.Add(tabs);tabs.BringToFront();
  var p1=new TabPage("감지 기록");events.Dock=DockStyle.Fill;events.View=View.Details;events.FullRowSelect=true;events.GridLines=false;events.Columns.Add("관측 시각",185);events.Columns.Add("항목",300);events.Columns.Add("접속 출처 / 근거",380);p1.Controls.Add(events);tabs.TabPages.Add(p1);
  var p2=new TabPage("AI 근거 검토");review.Multiline=true;review.ReadOnly=true;review.Dock=DockStyle.Fill;review.ScrollBars=ScrollBars.Vertical;review.BackColor=Color.White;review.BorderStyle=BorderStyle.None;review.Font=new Font("맑은 고딕",11);p2.Controls.Add(review);tabs.TabPages.Add(p2);
  var p3=new TabPage("승인 조치 · 재검증");actions.Dock=DockStyle.Fill;actions.View=View.Details;actions.FullRowSelect=true;actions.Columns.Add("조치",160);actions.Columns.Add("상태",160);actions.Columns.Add("대상 / 실행 결과",520);p3.Controls.Add(actions);tabs.TabPages.Add(p3);
  body.Controls.Clear();var layout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=3,Margin=new Padding(0)};layout.RowStyles.Add(new RowStyle(SizeType.Absolute,110));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,105));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));summary.Dock=DockStyle.Fill;cards.Dock=DockStyle.Fill;tabs.Dock=DockStyle.Fill;layout.Controls.Add(summary,0,0);layout.Controls.Add(cards,0,1);layout.Controls.Add(tabs,0,2);body.Controls.Add(layout);
  var p4=new TabPage("이 제품이 확인하는 범위");var scope=new TextBox{Dock=DockStyle.Fill,Multiline=true,ReadOnly=true,BackColor=Color.White,BorderStyle=BorderStyle.None,ScrollBars=ScrollBars.Vertical,Text="AI는 관측 근거를 검토하고 우선 점검 목록을 제안합니다.\r\n\r\n로그인 실패 · 보안 로그 삭제 · Windows Defender 감지 · 백신/방화벽 상태 · Windows 보안 업데이트를 확인합니다.\r\n\r\n침입이나 공격자의 AI 사용 여부를 이 프로그램만으로 확정하지 않습니다.\r\n\r\n관리자 승인 없이 패치나 IP 차단을 실행하지 않습니다. 승인된 차단은 공인 IPv4의 인바운드만 대상으로 하고 60분 후 해제합니다.\r\n\r\n패치 적용 후 설치 상태를 다시 확인합니다. 재부팅이 필요하면 확인 필요로 남기며 자동 재부팅하지 않습니다. 서비스 정상 여부와 백업은 관리자가 별도로 확인해야 합니다.\r\n\r\n기존 백신을 대체하지 않습니다. 이 창을 닫아도 SYSTEM 보안 수집 작업은 계속 실행됩니다."};p4.Controls.Add(scope);tabs.TabPages.Add(p4);
  tray.Icon=SystemIcons.Shield;tray.Text="NetChecker 디펜더 · 상태 확인";tray.Visible=stateOverride==null;tray.DoubleClick+=(s,e)=>{Show();WindowState=FormWindowState.Normal;Activate();};var menu=new ContextMenuStrip();menu.Items.Add("열기",null,(s,e)=>{Show();Activate();});menu.Items.Add("창 종료 (수집 유지)",null,(s,e)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
  FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}else{tray.Visible=false;tray.Dispose();timer.Stop();}};
  var scanPage=new TabPage("악성코드 검사");var scanButtons=new FlowLayoutPanel{Dock=DockStyle.Top,Height=48};
  foreach(string mode in new[]{"QuickScan","FullScan"}){string chosen=mode;var b=new Button{Text=mode=="QuickScan"?"빠른 검사":"전체 검사",Width=140,Height=35};b.Click+=(s,e)=>RunScan(chosen);scanButtons.Controls.Add(b);}
  var security=new Button{Text="Windows 보안 열기",Width=180,Height=35};security.Click+=(s,e)=>Process.Start(new ProcessStartInfo("windowsdefender:"){UseShellExecute=true});scanButtons.Controls.Add(security);
  scanStatus.Dock=DockStyle.Fill;scanStatus.Multiline=true;scanStatus.ReadOnly=true;scanStatus.BackColor=Color.White;scanStatus.ScrollBars=ScrollBars.Vertical;scanPage.Controls.Add(scanStatus);scanPage.Controls.Add(scanButtons);tabs.TabPages.Add(scanPage);
  timer.Interval=5000;timer.Tick+=(s,e)=>RefreshState(false);timer.Start();RefreshState(true);
 }
 static object Get(Dictionary<string,object> d,string k){object v;return d!=null&&d.TryGetValue(k,out v)?v:null;}
 static string Str(object v){return v==null?"미확인":Convert.ToString(v,CultureInfo.InvariantCulture);}
 static Dictionary<string,object> Obj(object v){return v as Dictionary<string,object>;}
 static IEnumerable Rows(object v){return v as IEnumerable??new object[0];}
 static string Local(object v){DateTimeOffset t;return v!=null&&DateTimeOffset.TryParse(Str(v),out t)?t.LocalDateTime.ToString("MM-dd HH:mm:ss"):"미확인";}
 void Card(string title,string value){var p=new Panel{Width=Math.Max(120,(cards.ClientSize.Width-50)/5),Height=78,BackColor=Color.White,Margin=new Padding(0,0,10,0)};p.Controls.Add(new Label{Text=title,Location=new Point(12,8),AutoSize=true,ForeColor=Color.Gray});p.Controls.Add(new Label{Text=value,Location=new Point(12,33),Width=165,Height=28,Font=new Font("맑은 고딕",14,FontStyle.Bold)});cards.Controls.Add(p);}
 string Flag(object value){return value==null?"미확인":Convert.ToBoolean(value)?"사용 중":"확인 필요";}
 void RunScan(string mode){
  if(MessageBox.Show("Windows Defender로 검사합니다. 기존 백신 정책에 따라 위협을 격리하거나 제거할 수 있습니다. 전체 검사는 시간이 오래 걸릴 수 있습니다. 실행할까요?","악성코드 검사",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
  string script=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"NetCheckerDefender","Scan-Defender.ps1");
  try{Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell\\v1.0\\powershell.exe"),"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \""+script+"\" -Mode "+mode){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden});scanStatus.Text="검사 실행을 요청했습니다. 관리자 권한 승인 후 검사 상태가 표시됩니다.";}catch{scanStatus.Text="검사를 실행하지 못했거나 관리자 권한 승인이 취소되었습니다.";}
 }
 void RefreshScan(){try{string path=Path.Combine(Path.GetDirectoryName(statePath),"scan.json");if(!File.Exists(path)){scanStatus.Text="검사 이력이 없습니다.\r\n\r\nWindows Defender 검사 엔진을 사용합니다. 다른 백신 사용 등으로 Defender가 비활성화되어 있으면 Windows 보안에서 현재 백신을 확인해 주세요.\r\n이 검사는 AI 침입 여부를 확정하는 기능이 아닙니다.";return;}var d=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path));scanStatus.Text="검사 유형: "+Str(Get(d,"mode"))+"\r\n상태: "+Str(Get(d,"detail"))+"\r\n시작: "+Local(Get(d,"started_at"))+"\r\n업데이트: "+Local(Get(d,"updated_at"));}catch{scanStatus.Text="검사 상태를 읽지 못했습니다.";}}
 void RefreshState(bool force){RefreshScan();
  try{
   if(!File.Exists(statePath)){headline.Text="등록·첫 수집을 기다리고 있습니다";detail.Text="관리자 대시보드에서 등록 승인 상태를 확인하세요.";return;}
   var text=File.ReadAllText(statePath);var data=json.Deserialize<Dictionary<string,object>>(text);DateTimeOffset stamp;bool stale=!DateTimeOffset.TryParse(Str(Get(data,"local_updated_at")),out stamp)||DateTimeOffset.UtcNow-stamp>TimeSpan.FromMinutes(90);
   if(!force&&text==last&&!stale)return;last=text;
   string state=Str(Get(data,"state"));bool pending=state=="pending",rejected=state=="rejected";stale=stale||state=="stale";
   int count=0;foreach(var a in Rows(Get(data,"alerts")))count++;
   headline.Text=pending?"관리자 등록 승인을 기다리고 있습니다":rejected?"등록이 해제되었습니다":stale?"최신 상태를 확인할 수 없습니다":state=="unavailable"?"수집·연결 확인이 필요합니다":count>0?"점검이 필요한 보안 신호가 있습니다":state=="partial"?"보안 모니터링 중 · 일부 항목 미확인":"보안 모니터링 중";
   headline.ForeColor=count>0||rejected?Color.FromArgb(178,68,38):Color.FromArgb(23,90,70);
   detail.Text="침입 확정이 아닌 관측 신호입니다. 조치는 관리자 승인 후 실행합니다.";time.Text=Str(Get(data,"label"))+"  ·  관측 "+Local(Get(data,"observed_at"))+"  ·  Agent 0.3.0";
   cards.Controls.Clear();var protection=Obj(Get(data,"protection"));var resources=Obj(Get(data,"resources"));
   Card("Defender 실시간 보호",Flag(stale?null:Get(protection,"realtime")));Card("Windows 방화벽",Flag(stale?null:Get(data,"firewall_enabled")));Card("점검 신호",count+"건");
   Card("보안 자료 전송","1시간마다");Card("업데이트 조회",Get(data,"inventory")==null?"미확인":"자료 수신");
   events.Items.Clear();foreach(var o in Rows(Get(data,"recent_events"))){var row=Obj(o);string code=Str(Get(row,"event_id"));string title=code=="4625"?"로그인 실패":code=="1102"?"보안 로그 삭제":code=="1116"?"백신 위협 감지":code=="1117"?"백신 조치 이벤트":code=="5001"?"백신 실시간 보호 중지":"보안 이벤트";events.Items.Add(new ListViewItem(new[]{Local(Get(row,"time")),title+" ("+code+")",Str(Get(row,"source_ip"))}));}
   foreach(var o in Rows(Get(data,"connections"))){var row=Obj(o);events.Items.Add(new ListViewItem(new[]{Local(Get(row,"time")),Str(Get(row,"summary")),Str(Get(row,"source_ip"))+" → 포트 "+Str(Get(row,"port"))}));}
   foreach(var a in Rows(Get(data,"alerts"))){var row=Obj(a);events.Items.Add(new ListViewItem(new[]{"점검 기준",Str(Get(row,"severity")),Str(Get(row,"summary"))}));}
   if(events.Items.Count==0)events.Items.Add(new ListViewItem(new[]{"최근 1시간","수집 범위 내 표시할 이벤트 없음","미수집 항목은 정상 판정하지 않습니다"}));
   var rv=Obj(Get(data,"review"));review.Text=rv==null?"아직 AI 검토 결과가 없습니다.\r\n관리자 대시보드에서 'AI 근거 검토'를 실행하세요.":"검토 근거 시각: "+Local(Get(rv,"based_on"))+"\r\n\r\n"+Str(Get(rv,"text"));
   actions.Items.Clear();foreach(var a in Rows(Get(data,"actions"))){var row=Obj(a);var result=Obj(Get(row,"result"));actions.Items.Add(new ListViewItem(new[]{Kind(Str(Get(row,"kind"))),State(Str(Get(row,"status"))),Str(Get(row,"target"))+" · "+(result==null?Str(Get(row,"reason")):Str(Get(result,"detail")))}));}
   tray.Text="NetChecker 디펜더 · "+(stale?"수집 지연":count>0?"점검 필요":"상태 확인");
  }catch{headline.Text="수집 상태를 읽지 못했습니다";detail.Text="다음 새로고침에서 다시 확인합니다. 모니터링 작업 상태를 확인하세요.";}
 }
 static string Kind(string v){return v=="update_install"?"보안 업데이트":v=="firewall_block"?"임시 IP 차단":v=="firewall_remove"?"차단 해제":v=="verify_action"?"재검증":v;}
 static string State(string v){switch(v){case "proposed":return "승인 대기";case "approved":return "실행 예약";case "claimed":return "실행·확인 중";case "verified":return "적용 상태 확인";case "verification_needed":return "추가 확인 필요";case "failed":return "실행 실패";case "outcome_unknown":return "결과 미확인";case "cancelled":return "취소";case "expired":return "승인 만료";default:return v;}}
}

