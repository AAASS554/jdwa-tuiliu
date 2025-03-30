#define MyAppName "抖音直播推流码捕获工具"
#define MyAppVersion "2.0"
#define MyAppPublisher "记得晚安科技"
#define MyAppURL "jdwa"
#define MyAppExeName "抖音直播推流码捕获工具.exe"

[Setup]
; 注意: AppId的值为单独标识此应用程序。
; 不要在其他安装程序中使用相同的AppId值。
AppId={{F8A3D742-8043-4B36-A90E-323F94E8B1C4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
; 删除以下行，创建一个新的GUID，并将其复制到此处
OutputDir=installer
OutputBaseFilename={#MyAppName}_Setup_{#MyAppVersion}
SetupIconFile=app.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

; 使用中文界面
[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 注意: 不要在"Source"后使用"Flags: ignoreversion"，否则将无法卸载
Source: "dist\抖音直播推流码捕获工具\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "app.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  ResultCode: Integer;

function InitializeSetup(): Boolean;
begin
  // 检查是否已安装旧版本
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1') then
  begin
    // 提示用户先卸载旧版本
    if MsgBox('检测到已安装旧版本，是否先卸载？', mbConfirmation, MB_YESNO) = IDYES then
    begin
      // 运行卸载程序
      ShellExec('', ExpandConstant('{uninstallexe}'), '', '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
    end;
  end;
  Result := True;
end;

[UninstallDelete]
Type: filesandordirs; Name: "{app}" 