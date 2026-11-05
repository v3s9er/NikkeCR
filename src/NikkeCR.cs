using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace NikkeCR {
    static class Program {
        [STAThread] static void Main(string[] args) {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args));
        }
    }
    sealed class MainForm : Form {
        readonly string root = AppDomain.CurrentDomain.BaseDirectory;
        readonly string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024, RecursionLimit = 100 };
        readonly Button detect = new Button(), repair = new Button();
        readonly Label[] cards = new Label[4];
        readonly Label phase = new Label();
        readonly TextBox evidence = new TextBox(), har = new TextBox();
        readonly CheckBox elevated = new CheckBox();
        readonly DataGridView table = new DataGridView();
        readonly DataGridView programs = new DataGridView(), relationships = new DataGridView(), planned = new DataGridView();
        readonly RichTextBox log = new RichTextBox();
        readonly ProgressBar progress = new ProgressBar();
        readonly Timer timer = new Timer();
        readonly LinkLabel folder = new LinkLabel();
        readonly Panel viewport = new Panel();
        readonly TableLayoutPanel layout = new TableLayoutPanel(), header = new TableLayoutPanel(), cardPanel = new TableLayoutPanel(), input = new TableLayoutPanel(), toolbar = new TableLayoutPanel();
        readonly Label heading = new Label(), legend = new Label();
        readonly Label evidenceLabel = new Label(), harLabel = new Label();
        readonly FlowLayoutPanel zoomPanel = new FlowLayoutPanel();
        readonly NumericUpDown textSize = new NumericUpDown();
        readonly TabControl tabs = new TabControl();
        readonly TabPage logPage = new TabPage("실행로그");
        bool arranging;
        Process child; string job = "", lastReport = "", lastHash = "", launchError = ""; int logChars = 0; bool busy = false;
        Dictionary<string, object> result;
        public MainForm(string[] args) {
            Text = "NikkeCR · NIKKE 탐지와 복구";
            AutoScaleDimensions = new SizeF(96F,96F); AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Malgun Gothic",12F); ClientSize = new Size(1280,880);
            MinimumSize = new Size(480,360); MaximumSize = Size.Empty;
            FormBorderStyle = FormBorderStyle.Sizable; MaximizeBox = true;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(16,23,36); ForeColor = Color.FromArgb(232,237,246);
            viewport.Dock=DockStyle.Fill;viewport.AutoScroll=true;Controls.Add(viewport);
            layout.ColumnCount=1;layout.RowCount=8;layout.Padding=new Padding(18);
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            for(int i=0;i<8;i++)layout.RowStyles.Add(new RowStyle(i==5?SizeType.Percent:SizeType.Absolute,i==5?100:40));
            viewport.Controls.Add(layout);

            header.Dock=DockStyle.Fill;header.ColumnCount=3;
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,140));header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,140));
            heading.Text="NikkeCR  |  감염 흔적 확인과 복구";heading.Dock=DockStyle.Fill;heading.TextAlign=ContentAlignment.MiddleLeft;heading.AutoEllipsis=true;
            header.Controls.Add(heading,0,0);StyleButton(detect,"탐지",Color.FromArgb(49,112,224));StyleButton(repair,"복구",Color.FromArgb(52,78,111));repair.Enabled=false;
            header.Controls.Add(detect,1,0);header.Controls.Add(repair,2,0);layout.Controls.Add(header,0,0);

            cardPanel.Dock=DockStyle.Fill;
            string[] names={"현재 위협","실제 유출 확인","복구 가능","추가 확인 필요"};
            for(int i=0;i<4;i++){cards[i]=new Label{Text=names[i]+"\n검사 전",Dock=DockStyle.Fill,Padding=new Padding(12,8,12,8),Margin=new Padding(3),BackColor=Color.FromArgb(29,41,60),TextAlign=ContentAlignment.MiddleLeft};cardPanel.Controls.Add(cards[i]);}
            layout.Controls.Add(cardPanel,0,1);

            input.Dock=DockStyle.Fill;evidenceLabel.Text="보존한 증거 폴더 (선택)";harLabel.Text="HTTP 기록 HAR 파일 (선택)";
            foreach(var label in new[]{evidenceLabel,harLabel}){label.Dock=DockStyle.Fill;label.TextAlign=ContentAlignment.MiddleLeft;}
            foreach(var box in new[]{evidence,har}){box.Dock=DockStyle.Fill;box.BackColor=Color.FromArgb(23,33,49);box.ForeColor=ForeColor;box.BorderStyle=BorderStyle.FixedSingle;box.AllowDrop=true;box.DragEnter+=(sender,e)=>{if(e.Data.GetDataPresent(DataFormats.FileDrop))e.Effect=DragDropEffects.Copy;};box.DragDrop+=(sender,e)=>{var paths=(string[])e.Data.GetData(DataFormats.FileDrop);if(paths.Length==1)((TextBox)sender).Text=paths[0];};}
            evidence.AccessibleName=evidenceLabel.Text;har.AccessibleName=harLabel.Text;
            input.Controls.Add(evidenceLabel);input.Controls.Add(evidence);input.Controls.Add(harLabel);input.Controls.Add(har);layout.Controls.Add(input,0,2);
            legend.Text="빨강: PC 귀속까지 확인된 유출  |  주황: 위협·노출·미검증 전송 기록  |  회색: 미확인\n0개는 유출 없음이나 완전 복구의 증명이 아닙니다.";
            legend.Dock=DockStyle.Fill;legend.ForeColor=Color.FromArgb(199,209,226);legend.TextAlign=ContentAlignment.MiddleLeft;layout.Controls.Add(legend,0,3);

            toolbar.Dock=DockStyle.Fill;elevated.Text="관리자 권한으로 탐지 (이벤트 로그·프로세스 접근 확대)";elevated.Dock=DockStyle.Fill;
            zoomPanel.Dock=DockStyle.Fill;zoomPanel.WrapContents=false;zoomPanel.FlowDirection=FlowDirection.LeftToRight;
            zoomPanel.Controls.Add(new Label{Text="글자 크기",AutoSize=true,Margin=new Padding(0,5,8,0)});
            textSize.Minimum=10;textSize.Maximum=20;textSize.Value=12;textSize.Width=65;textSize.AccessibleName="글자 크기";textSize.BackColor=Color.FromArgb(23,33,49);textSize.ForeColor=ForeColor;zoomPanel.Controls.Add(textSize);
            toolbar.Controls.Add(elevated);toolbar.Controls.Add(zoomPanel);layout.Controls.Add(toolbar,0,4);

            tabs.Dock=DockStyle.Fill;tabs.Padding=new Point(18,8);tabs.Multiline=true;
            ConfigureGrid(table,new[]{"분류","상태","항목","근거·한계"},new[]{14F,19F,25F,42F},new[]{100,135,170,260});AddGridTab(table,"탐지 결과");
            ConfigureGrid(programs,new[]{"이름","버전","게시자","설치 위치 · 정상 판정 아님"},new[]{25F,15F,22F,38F},new[]{150,100,140,250});AddGridTab(programs,"설치 프로그램");
            ConfigureGrid(relationships,new[]{"종류","이름","참조 파일 검사","참조 경로"},new[]{15F,24F,23F,38F},new[]{100,150,150,250});AddGridTab(relationships,"실행 연결");
            ConfigureGrid(planned,new[]{"조치","대상","근거","범위"},new[]{20F,30F,30F,20F},new[]{130,190,190,140});AddGridTab(planned,"복구 계획");
            log.Dock=DockStyle.Fill;log.ReadOnly=true;log.BackColor=Color.FromArgb(8,14,24);log.ForeColor=Color.FromArgb(173,206,189);log.WordWrap=false;log.DetectUrls=false;log.BorderStyle=BorderStyle.None;log.AccessibleName="실행로그 내용";
            log.Text="NikkeCR 0.4.4-preview\n검사 전 · 파일 내용이나 비밀번호를 로그에 출력하지 않습니다.\n";
            logPage.Padding=new Padding(12);logPage.BackColor=log.BackColor;logPage.Controls.Add(log);tabs.TabPages.Add(logPage);layout.Controls.Add(tabs,0,5);
            phase.Text="탐지를 누르면 검사가 시작됩니다. 진행 내용은 실행로그 탭에서 확인하세요.";phase.Dock=DockStyle.Fill;phase.TextAlign=ContentAlignment.MiddleLeft;layout.Controls.Add(phase,0,6);
            var footer=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            progress.Dock=DockStyle.Fill;progress.Margin=new Padding(0,7,12,7);footer.Controls.Add(progress,0,0);
            folder.Text="결과·백업 폴더 열기";folder.AutoSize=true;folder.Dock=DockStyle.Fill;folder.TextAlign=ContentAlignment.MiddleRight;folder.LinkColor=Color.FromArgb(145,190,255);folder.Enabled=false;footer.Controls.Add(folder,1,0);layout.Controls.Add(footer,0,7);

            detect.Click+=(sender,e)=>Start("Detect");repair.Click+=(sender,e)=>Start("Repair");
            folder.LinkClicked+=(sender,e)=>{if(Directory.Exists(job))Process.Start(new ProcessStartInfo("explorer.exe",Quote(job)){UseShellExecute=true});};
            textSize.ValueChanged+=(sender,e)=>ApplyTextSize();viewport.Resize+=(sender,e)=>ArrangeContent();
            timer.Interval=700;timer.Tick+=(sender,e)=>Poll();timer.Start();
            FormClosing+=(sender,e)=>{if(busy){e.Cancel=true;MessageBox.Show(this,"검사·복구가 실행 중입니다. 결과가 기록될 때까지 창을 유지합니다.","NikkeCR");}};
            Shown+=(sender,e)=>{var area=Screen.FromControl(this).WorkingArea;if(Width>area.Width||Height>area.Height){Size=new Size(Math.Min(Width,area.Width-24),Math.Min(Height,area.Height-24));Location=new Point(area.Left+(area.Width-Width)/2,area.Top+(area.Height-Height)/2);}ArrangeContent();};
            if(args.Length==2&&args[0]=="--view-report")Shown+=(sender,e)=>{try{string path=Path.GetFullPath(args[1]);LoadReport(path,false);job=Path.GetDirectoryName(path);folder.Enabled=true;phase.Text="저장한 결과 보기 · 복구는 새로 탐지한 뒤 가능합니다.";LoadSavedLog();}catch(Exception x){MessageBox.Show(this,x.Message);}};
            ApplyTextSize();
        }
        void StyleButton(Button b,string text,Color bg){b.Text=text;b.Dock=DockStyle.Fill;b.Margin=new Padding(6);b.BackColor=bg;b.ForeColor=Color.White;b.FlatStyle=FlatStyle.Flat;b.FlatAppearance.BorderSize=0;}
        void ConfigureGrid(DataGridView grid,string[] titles,float[] weights,int[] minimums){
            grid.Dock=DockStyle.Fill;grid.ReadOnly=true;grid.AllowUserToAddRows=false;grid.AllowUserToDeleteRows=false;grid.AllowUserToResizeRows=false;grid.RowHeadersVisible=false;grid.MultiSelect=false;grid.AutoGenerateColumns=false;grid.BorderStyle=BorderStyle.None;
            grid.BackgroundColor=Color.FromArgb(23,33,49);grid.EnableHeadersVisualStyles=false;grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(36,50,72);grid.ColumnHeadersDefaultCellStyle.ForeColor=ForeColor;grid.ColumnHeadersDefaultCellStyle.WrapMode=DataGridViewTriState.True;grid.ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            grid.DefaultCellStyle.BackColor=grid.BackgroundColor;grid.DefaultCellStyle.ForeColor=ForeColor;grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(47,66,96);grid.DefaultCellStyle.SelectionForeColor=Color.White;grid.DefaultCellStyle.Padding=new Padding(8);grid.DefaultCellStyle.WrapMode=DataGridViewTriState.True;grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(27,38,55);
            grid.GridColor=Color.FromArgb(46,60,79);grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect;grid.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.AllCells;
            for(int i=0;i<titles.Length;i++)grid.Columns.Add(new DataGridViewTextBoxColumn{HeaderText=titles[i],AutoSizeMode=DataGridViewAutoSizeColumnMode.Fill,FillWeight=weights[i],MinimumWidth=minimums[i]});
            grid.CellDoubleClick+=(sender,e)=>{if(e.RowIndex>=0)ShowDetails(grid,e.RowIndex);};
            grid.KeyDown+=(sender,e)=>{if(e.KeyCode==Keys.Enter&&grid.CurrentRow!=null){e.Handled=true;e.SuppressKeyPress=true;ShowDetails(grid,grid.CurrentRow.Index);}};
        }
        void AddGridTab(DataGridView grid,string title){
            var page=new TabPage(title){BackColor=Color.FromArgb(23,33,49),Padding=new Padding(6)};
            var hint=new Label{Text="항목 두 번 클릭 / Enter: 상세 보기 · 열 경계 드래그: 너비 조절",Dock=DockStyle.Top,AutoSize=false,Height=36,Padding=new Padding(8,5,8,5),ForeColor=Color.FromArgb(184,199,220),TextAlign=ContentAlignment.MiddleLeft};
            page.Resize+=(sender,e)=>{hint.Height=TextRenderer.MeasureText(hint.Text,Font,new Size(Math.Max(160,page.ClientSize.Width-32),Int32.MaxValue),TextFormatFlags.WordBreak).Height+14;};
            page.Controls.Add(grid);page.Controls.Add(hint);tabs.TabPages.Add(page);
        }
        void ApplyTextSize(){
            Font=new Font("Malgun Gothic",(float)textSize.Value);heading.Font=new Font(Font.FontFamily,Font.Size+6,FontStyle.Bold);
            foreach(var b in new[]{detect,repair})b.Font=new Font(Font.FontFamily,Font.Size+1,FontStyle.Bold);
            foreach(var card in cards)card.Font=new Font(Font.FontFamily,Font.Size,FontStyle.Bold);
            log.Font=new Font("Consolas",Font.Size);tabs.Font=Font;
            foreach(var grid in new[]{table,programs,relationships,planned}){grid.Font=Font;grid.DefaultCellStyle.Font=Font;grid.ColumnHeadersDefaultCellStyle.Font=new Font(Font,FontStyle.Bold);grid.RowTemplate.MinimumHeight=Font.Height*2+12;foreach(DataGridViewRow row in grid.Rows)row.MinimumHeight=grid.RowTemplate.MinimumHeight;}
            foreach(TabPage page in tabs.TabPages)foreach(Control childControl in page.Controls)if(childControl is Label)childControl.Height=TextRenderer.MeasureText(childControl.Text,Font,new Size(Math.Max(160,page.ClientSize.Width-32),Int32.MaxValue),TextFormatFlags.WordBreak).Height+14;
            ArrangeContent();
        }
        void ArrangeContent(){
            if(arranging||viewport.ClientSize.Width<1||cards[3]==null)return;arranging=true;
            try{
                layout.SuspendLayout();int unit=Math.Max(16,Font.Height);int width=Math.Max(440,viewport.ClientSize.Width);float scale=unit/20F;
                bool narrow=width<820*scale,stack=width<650*scale;int pad=layout.Padding.Horizontal+12;
                header.ColumnStyles[1].Width=header.ColumnStyles[2].Width=Math.Max(98,unit*6);
                heading.Text=width<980*scale?"NikkeCR":"NikkeCR  |  감염 흔적 확인과 복구";
                int cardColumns=narrow?2:4;
                if(cardPanel.ColumnCount!=cardColumns){cardPanel.SuspendLayout();cardPanel.Controls.Clear();cardPanel.ColumnStyles.Clear();cardPanel.RowStyles.Clear();cardPanel.ColumnCount=cardColumns;cardPanel.RowCount=4/cardColumns;for(int i=0;i<cardColumns;i++)cardPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100F/cardColumns));for(int i=0;i<cardPanel.RowCount;i++)cardPanel.RowStyles.Add(new RowStyle(SizeType.Percent,100F/cardPanel.RowCount));for(int i=0;i<4;i++)cardPanel.Controls.Add(cards[i],i%cardColumns,i/cardColumns);cardPanel.ResumeLayout();}
                int inputColumns=stack?1:2;
                if(input.ColumnCount!=inputColumns){input.SuspendLayout();input.Controls.Clear();input.ColumnStyles.Clear();input.RowStyles.Clear();input.ColumnCount=inputColumns;input.RowCount=stack?4:2;input.ColumnStyles.Add(new ColumnStyle(stack?SizeType.Percent:SizeType.Absolute,stack?100:245));if(!stack)input.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));for(int i=0;i<input.RowCount;i++)input.RowStyles.Add(new RowStyle(SizeType.Percent,100F/input.RowCount));input.Controls.Add(evidenceLabel,0,0);input.Controls.Add(evidence,stack?0:1,stack?1:0);input.Controls.Add(harLabel,0,stack?2:1);input.Controls.Add(har,stack?0:1,stack?3:1);input.ResumeLayout();}
                if(!stack)input.ColumnStyles[0].Width=unit*12;
                int toolColumns=narrow?1:2;
                if(toolbar.ColumnCount!=toolColumns){toolbar.SuspendLayout();toolbar.Controls.Clear();toolbar.ColumnStyles.Clear();toolbar.RowStyles.Clear();toolbar.ColumnCount=toolColumns;toolbar.RowCount=narrow?2:1;toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));if(!narrow)toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,195));for(int i=0;i<toolbar.RowCount;i++)toolbar.RowStyles.Add(new RowStyle(SizeType.Percent,100F/toolbar.RowCount));toolbar.Controls.Add(elevated,0,0);toolbar.Controls.Add(zoomPanel,narrow?0:1,narrow?1:0);toolbar.ResumeLayout();}
                if(!narrow)toolbar.ColumnStyles[1].Width=unit*10;
                int legendHeight=TextRenderer.MeasureText(legend.Text,Font,new Size(Math.Max(300,width-pad-20),Int32.MaxValue),TextFormatFlags.WordBreak).Height+12;
                int[] heights={unit*2+12,(unit*2+24)*(narrow?2:1),unit*(stack?6:3)+12,legendHeight,unit*(narrow?3:1)+18,0,unit+16,unit+12};
                int minimum=layout.Padding.Vertical+unit*7+24;for(int i=0;i<heights.Length;i++)if(i!=5){layout.RowStyles[i].Height=heights[i];minimum+=heights[i];}
                if(viewport.ClientSize.Height<minimum)width=Math.Max(440,width-SystemInformation.VerticalScrollBarWidth);
                layout.Size=new Size(width-6,Math.Max(viewport.ClientSize.Height-6,minimum));
            }finally{layout.ResumeLayout();arranging=false;}
        }
        void ShowDetails(DataGridView grid,int rowIndex){
            var row=grid.Rows[rowIndex];var text=new StringBuilder();foreach(DataGridViewColumn column in grid.Columns){text.AppendLine(column.HeaderText);text.AppendLine(Convert.ToString(row.Cells[column.Index].Value));text.AppendLine();}
            var record=row.Tag as Dictionary<string,object>;if(record!=null)foreach(string key in new[]{"Source","At","Target"}){string value=Str(record,key);if(value.Length>0){text.AppendLine(key=="Source"?"근거 위치":key=="At"?"기록 시각":"대상");text.AppendLine(value);text.AppendLine();}}
            if(record==null&&grid==relationships&&row.Cells[3].ToolTipText.Length>0){text.AppendLine("등록 원본 위치");text.AppendLine(row.Cells[3].ToolTipText);}
            using(var dialog=new Form{Text="상세 내용 · NikkeCR",StartPosition=FormStartPosition.CenterParent,ClientSize=new Size(Math.Min(960,Screen.FromControl(this).WorkingArea.Width-80),Math.Min(650,Screen.FromControl(this).WorkingArea.Height-100)),MinimumSize=new Size(420,300),Font=Font,BackColor=BackColor,ForeColor=ForeColor}){
                var details=new TextBox{Multiline=true,ReadOnly=true,Dock=DockStyle.Fill,ScrollBars=ScrollBars.Vertical,WordWrap=true,BorderStyle=BorderStyle.None,BackColor=Color.FromArgb(23,33,49),ForeColor=ForeColor,Text=text.ToString(),AccessibleName="상세 내용"};
                var close=new Button{Text="닫기",Dock=DockStyle.Bottom,Height=48,DialogResult=DialogResult.Cancel};dialog.Padding=new Padding(18);dialog.Controls.Add(details);dialog.Controls.Add(close);dialog.CancelButton=close;dialog.ShowDialog(this);
            }
        }
        void LoadSavedLog(){
            string path=Path.Combine(job,"progress.log");if(!File.Exists(path))return;
            using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){if(f.Length>8*1024*1024){log.Text="저장된 로그가 8 MiB보다 큽니다. 결과 폴더에서 원본 progress.log를 확인하세요.";return;}using(var reader=new StreamReader(f,Encoding.UTF8))log.Text=reader.ReadToEnd();}
        }
        static string Quote(string s){if(s.IndexOfAny(new[]{'"','\r','\n','\0'})>=0 || s.EndsWith("\\"))throw new InvalidOperationException("지원하지 않는 경로 문자입니다.");return "\""+s+"\"";}
        static string Sha(string path){using(var s=SHA256.Create())using(var f=File.OpenRead(path))return BitConverter.ToString(s.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
        static void AssertNoReparse(string path){
            for(string current=Path.GetFullPath(path);current!=null;current=Path.GetDirectoryName(current)){
                try{if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("링크된 배포 경로는 지원하지 않습니다: "+current);}
                catch(FileNotFoundException){}catch(DirectoryNotFoundException){}
            }
        }
        Dictionary<string,object> Read(string p){using(var f=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))using(var r=new StreamReader(f,Encoding.UTF8)){if(f.Length>32*1024*1024)throw new InvalidDataException("결과 파일 크기 제한 초과");return json.Deserialize<Dictionary<string,object>>(r.ReadToEnd());}}
        static IEnumerable Items(object o){return o as IEnumerable ?? new object[0];}
        static string Str(Dictionary<string,object> d,string k){object v;return d.TryGetValue(k,out v)&&v!=null?Convert.ToString(v):"";}
        static int Num(Dictionary<string,object>d,string k){int n;return Int32.TryParse(Str(d,k),out n)?n:0;}
        void VerifyPackage(){
            string manifest=Path.Combine(root,"NikkeCR-SHA256.json");AssertNoReparse(manifest);
            var m=Read(manifest);if(Str(m,"Version")!="0.4.4-preview")throw new InvalidDataException("지원하지 않는 배포 버전");int count=0;
            foreach(Dictionary<string,object> entry in Items(m["Files"])){string relative=Str(entry,"Path");if(Path.IsPathRooted(relative)||relative.Contains("..")||relative.Contains(":"))throw new InvalidDataException("잘못된 배포 파일 경로");string p=Path.GetFullPath(Path.Combine(root,relative));AssertNoReparse(p);if(Sha(p)!=Str(entry,"SHA256"))throw new InvalidDataException("배포 파일이 변경되었습니다: "+relative);count++;}if(count<10)throw new InvalidDataException("불완전한 배포 목록");
        }
        void Start(string mode){if(busy)return;try{
            VerifyPackage();string ev=evidence.Text.Trim(), hp=har.Text.Trim();if(ev.Length>0){ev=Path.GetFullPath(ev);if(!Directory.Exists(ev))throw new IOException("증거 폴더가 없습니다.");}if(hp.Length>0){hp=Path.GetFullPath(hp);if(!File.Exists(hp))throw new IOException("HAR 파일이 없습니다.");}
            if(mode=="Repair"){
                if(result==null||lastReport.Length==0||Sha(lastReport)!=lastHash)throw new InvalidOperationException("탐지 결과가 변경되었습니다. 다시 탐지하세요.");
                var b=new StringBuilder("검토한 탐지 계획에서 아래 조치를 수행합니다.\n원본 백업 후 재검증하며 실패한 항목은 남깁니다.\n\n");int c=0;
                foreach(Dictionary<string,object> a in Items(result["RepairPlan"])){if(c++<20)b.AppendLine(Str(a,"Kind")+" · "+Str(a,"Target"));}
                if(c>20)b.AppendLine("외 "+(c-20)+"개 (result.json의 RepairPlan 확인)");int settings=0;foreach(var a in Items(result["SettingsPlan"]))settings++;
                b.AppendLine("\n추가로 백업 후 제거할 확정 조건의 사용자 설정: "+settings+"개");b.AppendLine("\n런처의 네트워크를 차단할 수 있습니다. 앱 종료·재부팅·전체 초기화는 자동 수행하지 않습니다.\n계속하면 Windows 관리자 승인 창이 표시됩니다.");
                if(MessageBox.Show(this,b.ToString(),"복구 계획 확인",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return;
            }
            job=Path.Combine(profile,"NikkeCR-Evidence","Runs",DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N"));
            string script=Path.Combine(root,"scripts","Invoke-NikkeCR.ps1");var args=new StringBuilder("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+Quote(script)+" -Mode "+mode+" -TargetProfile "+Quote(profile)+" -JobRoot "+Quote(job));
            if(ev.Length>0)args.Append(" -EvidenceRoot "+Quote(ev));if(hp.Length>0)args.Append(" -HarPath "+Quote(hp));if(mode=="Repair")args.Append(" -PreviousReport "+Quote(lastReport)+" -PreviousSHA256 "+lastHash);
            bool needsAdmin=mode=="Repair"||elevated.Checked;
            var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell","v1.0","powershell.exe"),args.ToString()){UseShellExecute=needsAdmin,WindowStyle=ProcessWindowStyle.Hidden,CreateNoWindow=true,WorkingDirectory=root};if(needsAdmin)start.Verb="runas";
            launchError="";if(!needsAdmin){start.RedirectStandardError=true;start.RedirectStandardOutput=true;}
            child=new Process{StartInfo=start};if(!needsAdmin){child.OutputDataReceived+=(s,e)=>{};child.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)lock(json){if(launchError.Length<4096)launchError+=e.Data+Environment.NewLine;}};}
            child.Start();var handle=child.Handle;if(!needsAdmin){child.BeginOutputReadLine();child.BeginErrorReadLine();}busy=true;detect.Enabled=false;repair.Enabled=false;evidence.Enabled=false;har.Enabled=false;elevated.Enabled=false;folder.Enabled=true;logChars=0;log.Clear();tabs.SelectedTab=logPage;progress.Value=0;phase.Text=mode=="Repair"?"복구 작업을 준비합니다…":"탐지 작업을 준비합니다…";
        }catch(Win32Exception x){phase.Text=x.NativeErrorCode==1223?"관리자 승인이 취소되었습니다. 조치는 시작하지 않았습니다.":"실행 실패: "+x.Message;}catch(Exception x){phase.Text="실행 실패";MessageBox.Show(this,x.Message,"NikkeCR",MessageBoxButtons.OK,MessageBoxIcon.Warning);}}
        void Poll(){if(!busy)return;try{string p=Path.Combine(job,"progress.log");if(File.Exists(p)&&logChars>=0){using(var f=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){if(f.Length>8*1024*1024){log.AppendText("\n로그가 8 MiB를 초과해 화면 갱신을 중단했습니다. 결과 폴더에서 확인하세요.\n");logChars=-1;}else{string t;using(var r=new StreamReader(f,Encoding.UTF8))t=r.ReadToEnd();if(t.Length>logChars){log.AppendText(t.Substring(logChars));logChars=t.Length;log.SelectionStart=log.TextLength;log.ScrollToCaret();}}}}
            p=Path.Combine(job,"status.json");if(File.Exists(p)){var s=Read(p);phase.Text=Str(s,"Stage");progress.Value=Math.Max(0,Math.Min(100,Num(s,"Percent")));}
            if(child.HasExited){child.WaitForExit();int exit=child.ExitCode;child.Dispose();child=null;busy=false;detect.Enabled=true;evidence.Enabled=true;har.Enabled=true;elevated.Enabled=true;p=Path.Combine(job,"result.json");if(File.Exists(p)){LoadReport(p,true);if(tabs.SelectedTab==logPage)tabs.SelectedIndex=0;if(exit!=0)phase.Text="일부 조치 실패 · 결과와 로그를 확인하세요.";}else{repair.Enabled=false;phase.Text="결과 생성 실패 · 안전 판정 불가 (종료 코드 "+exit+")";if(log.TextLength==0&&launchError.Length>0){log.AppendText("초기 실행 단계에서 오류가 발생했습니다. PowerShell, 배포 폴더 및 결과 폴더 권한을 확인하세요.\n");MessageBox.Show(this,launchError,"초기 실행 진단 · 외부 공유 전 경로 확인",MessageBoxButtons.OK,MessageBoxIcon.Warning);}}}
        }catch(IOException){}catch(Exception x){log.AppendText("\n결과 표시 오류: "+x.Message+"\n");}}
        void LoadReport(string path,bool trusted){
            var d=Read(path);table.Rows.Clear();programs.Rows.Clear();relationships.Rows.Clear();planned.Rows.Clear();result=d;string[] names={"현재 위협","실제 유출 확인",Str(d,"Mode")=="Repair"?"이번 복구 계획":"복구 계획 항목","추가 확인 필요"};string[] keys={"ThreatCount","ConfirmedExfiltrationCount","RepairableCount","ReviewCount"};for(int i=0;i<4;i++){cards[i].Text=names[i]+"\n"+Num(d,keys[i])+"개";cards[i].ForeColor=(i==1&&Num(d,keys[i])>0)?Color.FromArgb(255,118,118):ForeColor;}
            foreach(Dictionary<string,object> r in Items(d["Rows"])){string status=Str(r,"Status");int n=table.Rows.Add(Str(r,"Category"),StatusLabel(status),Str(r,"Title"),Str(r,"Reason"));table.Rows[n].Tag=r;table.Rows[n].Cells[2].ToolTipText=Str(r,"Source");if(status=="ConfirmedExfiltration")table.Rows[n].DefaultCellStyle.ForeColor=Color.FromArgb(255,118,118);else if(status=="ConfirmedThreat"||status=="PotentialExposure"||status=="CollectionTrace"||status=="CapturedTransfer")table.Rows[n].DefaultCellStyle.ForeColor=Color.FromArgb(255,210,138);else if(status=="Repaired")table.Rows[n].DefaultCellStyle.ForeColor=Color.FromArgb(135,220,161);}
            if(d.ContainsKey("Programs"))foreach(Dictionary<string,object> r in Items(d["Programs"]))programs.Rows.Add(Str(r,"Name"),Str(r,"Version"),Str(r,"Publisher"),Str(r,"Location"));
            if(d.ContainsKey("Relationships"))foreach(Dictionary<string,object> r in Items(d["Relationships"])){int n=relationships.Rows.Add(Str(r,"Kind"),Str(r,"Name"),Str(r,"FileStatus"),Str(r,"FilePath"));relationships.Rows[n].Cells[3].ToolTipText=Str(r,"Source");}
            foreach(Dictionary<string,object> r in Items(d["RepairPlan"]))planned.Rows.Add(ActionLabel(Str(r,"Kind")),Str(r,"Target"),Str(r,"Reason"),Str(d,"Mode")=="Repair"?"복구 시작 시 계획 · 결과는 탐지 결과 탭 확인":"승인 후 재검증");
            foreach(Dictionary<string,object> r in Items(d["SettingsPlan"]))planned.Rows.Add("사용자 설정 값 제거",Str(r,"Path")+" / "+Str(r,"Name"),Str(r,"Reason"),"원래 값 백업 후 해당 값만 제거");
            if(Num(d,"ConfirmedExfiltrationCount")==0)cards[1].Text="실제 유출 미확정\n전송 기록 "+Num(d,"CapturedTransferCount")+"개";
            lastReport=trusted&&Str(d,"Mode")=="Detect"?path:"";lastHash=lastReport.Length>0?Sha(path):"";repair.Enabled=lastReport.Length>0&&Num(d,"RepairableCount")>0;phase.Text="설치 프로그램 "+Num(d,"InstalledProgramCount")+"개 · 시작 연결 "+Num(d,"StartupRelationshipCount")+"개 · 전체 안전 판정 아님";
        }
        static string StatusLabel(string s){switch(s){case "ConfirmedExfiltration":return "실제 유출 확인*";case "CapturedTransfer":return "전송 기록 · PC 귀속 미확인";case "ConfirmedThreat":return "알려진 위협";case "PotentialExposure":return "노출 가능";case "CollectionTrace":return "수집 흔적 · 유출 미확정";case "CapabilityOnly":return "기능 확인 · 실행 미확정";case "CoverageGap":return "검사하지 못함";case "Review":return "추가 확인 필요";case "Repaired":return "복구 후 확인";case "Failed":return "복구 실패";default:return s;}}
        static string ActionLabel(string s){switch(s){case "BlockC2":return "공격자 IP 차단";case "BlockDomains":return "공격자 도메인 차단";case "BlockLauncher":return "런처 통신 차단";case "RemoveUserOverride":return "사용자 COM 변조 제거";case "QuarantineDll":return "악성 DLL 보존·격리";case "IsolateCache":return "런처 캐시 보존·격리";default:return s;}}
    }
}
