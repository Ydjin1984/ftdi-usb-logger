param([string]$ProcName = 'ME72 Quickflash', [string]$Out = 'shot.png')
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing, System.Windows.Forms
$root = [System.Windows.Automation.AutomationElement]::RootElement
$procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
if (-not $procs) { Write-Output "process '$ProcName' not found"; exit 1 }
$p = $procs[0]
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Write-Output 'no window'; exit 1 }
$r = $win.Current.BoundingRectangle
if ($r.Width -lt 10) { Write-Output 'window rect empty'; exit 1 }
$bmp = New-Object System.Drawing.Bitmap([int]$r.Width, [int]$r.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, (New-Object System.Drawing.Size([int]$r.Width, [int]$r.Height)))
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Output ("saved " + $Out + " " + [int]$r.Width + "x" + [int]$r.Height)
