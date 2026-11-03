# Private owner display. Native shown/closed evidence is not human confirmation.
$ErrorActionPreference='Stop'
$ucForm=$null; $ucTimer=$null; $ucInput=$null
$ucWatch=[Diagnostics.Stopwatch]::StartNew()
$ucState=@{phase='INPUT';v=2;ok=$false;failure='';shown=$false;nativeVisible=$false;onScreen=$false;foreground=$false;closeReason='failed';session=[Diagnostics.Process]::GetCurrentProcess().SessionId;elapsedMs=0;shownElapsedMs=-1;bounds=@{left=0;top=0;width=0;height=0}}
try {
 $ucInput=[Console]::In.ReadToEnd() | ConvertFrom-Json
 $ucNow=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
 if($ucInput.code -isnot [string] -or $ucInput.code.Length -gt 8192 -or [long]$ucInput.expiresAt -le $ucNow -or [long]$ucInput.expiresAt -gt ($ucNow+900000)){throw 'DISPLAY_EXPIRED_BEFORE_SHOW'}
 $ucState.phase='ASSEMBLY'
 Add-Type -AssemblyName System.Windows.Forms
 $ucState.phase='NATIVE_SETUP'
 Add-Type -TypeDefinition @"
using System;using System.Text;using System.Runtime.InteropServices;
public static class UCDisplayObservation {
 [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr h,int kind,StringBuilder text,int length,out int needed);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
 public static bool Foreground(IntPtr h){return h==GetForegroundWindow();}
 static string Name(IntPtr h){var text=new StringBuilder(256);int size;if(h==IntPtr.Zero||!GetUserObjectInformation(h,2,text,512,out size))return null;return text.ToString();}
 public static bool Allowed(){if(!Environment.UserInteractive||System.Diagnostics.Process.GetCurrentProcess().SessionId==0)return false;var own=Name(GetThreadDesktop(GetCurrentThreadId()));var input=OpenInputDesktop(0,false,1);try{return own=="Default"&&Name(input)==own;}finally{if(input!=IntPtr.Zero)CloseDesktop(input);}}
}
"@
 $ucState.phase='DESKTOP_CHECK'
 if(-not [UCDisplayObservation]::Allowed()){throw 'DISPLAY_DESKTOP_UNAVAILABLE'}
 if([long]$ucInput.expiresAt -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()){throw 'DISPLAY_EXPIRED_BEFORE_SHOW'}
 $ucState.phase='BUILD_FORM'
 $ucForm=New-Object Windows.Forms.Form
 $ucForm.Text='UniversalControl private pairing code';$ucForm.Width=690;$ucForm.Height=235
 $ucForm.StartPosition='CenterScreen';$ucForm.ShowInTaskbar=$true;$ucForm.WindowState='Normal'
 $ucLabel=New-Object Windows.Forms.Label;$ucLabel.SetBounds(16,12,640,45);$ucLabel.Text='Copy only to the intended device. Clipboard history or screen capture may retain this secret. Approve only a matching device fingerprint.'
 $ucText=New-Object Windows.Forms.TextBox;$ucText.SetBounds(16,63,640,26);$ucText.ReadOnly=$true;$ucText.UseSystemPasswordChar=$true;$ucText.Text=$ucInput.code
 $ucReveal=New-Object Windows.Forms.CheckBox;$ucReveal.SetBounds(16,101,430,26);$ucReveal.Text='Reveal code for manual selection/copy';$ucReveal.Add_CheckedChanged({$ucText.UseSystemPasswordChar=-not $ucReveal.Checked})
 $ucRemaining=New-Object Windows.Forms.Label;$ucRemaining.SetBounds(16,137,640,25)
 $ucForm.Controls.AddRange(@($ucLabel,$ucText,$ucReveal,$ucRemaining))
 $ucForm.Add_Shown({try{$ucState.phase='SHOWN';$ucState.shown=$true;$ucState.shownElapsedMs=[long]$ucWatch.ElapsedMilliseconds;$ucForm.Activate()}catch{$ucState.failure='DISPLAY_EVENT_FAILED';$ucState.closeReason='failed';$ucForm.Close()}})
 $ucTimer=New-Object Windows.Forms.Timer;$ucTimer.Interval=250
 $ucTimer.Add_Tick({try{
  $ucVisible=$ucForm.Visible -and [UCDisplayObservation]::IsWindowVisible($ucForm.Handle)
  $ucOnScreen=$false;foreach($ucScreen in [Windows.Forms.Screen]::AllScreens){if($ucScreen.WorkingArea.IntersectsWith($ucForm.Bounds)){$ucOnScreen=$true}}
  if($ucVisible){$ucState.nativeVisible=$true};if($ucVisible -and $ucOnScreen){$ucState.onScreen=$true}
  if([UCDisplayObservation]::Foreground($ucForm.Handle)){$ucState.foreground=$true}
  $ucState.bounds=@{left=$ucForm.Left;top=$ucForm.Top;width=$ucForm.Width;height=$ucForm.Height}
  $ucLeft=[Math]::Max(0,[long]$ucInput.expiresAt-[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
  $ucRemaining.Text=('Expires in '+[Math]::Ceiling($ucLeft/1000)+' seconds. Closing this display does not approve a device.')
  if($ucLeft -le 0){$ucState.closeReason='expired';$ucForm.Close()}
  elseif(-not $ucState.shown -and $ucWatch.ElapsedMilliseconds -gt 5000){$ucState.failure='DISPLAY_NOT_SHOWN';$ucState.closeReason='failed';$ucForm.Close()}
 }catch{$ucState.failure='DISPLAY_EVENT_FAILED';$ucState.closeReason='failed';$ucForm.Close()}})
 $ucForm.Add_FormClosing({$ucTimer.Stop();$ucText.Text='';$ucInput.code='';if($ucState.closeReason -eq 'failed' -and $ucState.failure -eq ''){$ucState.closeReason='closed'}})
 $ucState.phase='SHOW_DIALOG';$ucTimer.Start();[void]$ucForm.ShowDialog()
 $ucState.ok=($ucState.failure -eq '') -and $ucState.shown -and $ucState.nativeVisible -and $ucState.onScreen
 if(-not $ucState.ok){if(-not $ucState.shown -or -not $ucState.nativeVisible -or -not $ucState.onScreen){$ucState.failure='DISPLAY_NOT_SHOWN'}}
}catch{$ucState.failure='DISPLAY_NATIVE_FAILED';if($_.Exception.Message -in @('DISPLAY_EXPIRED_BEFORE_SHOW','DISPLAY_DESKTOP_UNAVAILABLE')){$ucState.failure=$_.Exception.Message}}
finally{if($null -ne $ucTimer){$ucTimer.Stop();$ucTimer.Dispose()};if($null -ne $ucInput){$ucInput.code=''};if($null -ne $ucForm){$ucForm.Dispose()};$ucState.elapsedMs=[long]$ucWatch.ElapsedMilliseconds}
$ucState | ConvertTo-Json -Depth 4 -Compress
if(-not $ucState.ok){exit 1}
