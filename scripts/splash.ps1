# Splash-экран при старте продукта: логотип + «запуск…», закрывается,
# когда движок ответил на /api/health (или по таймауту).
param(
    [int]$Port = 7811,
    [string]$Logo = "",
    [int]$Seconds = 60
)
$ErrorActionPreference = "SilentlyContinue"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

if (-not $Logo -or -not (Test-Path $Logo)) {
    $candidate = Join-Path $PSScriptRoot "splash.png"
    if (Test-Path $candidate) { $Logo = $candidate }
}

$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.BackColor = [System.Drawing.Color]::FromArgb(11, 14, 18)
$form.TopMost = $true
$form.ShowInTaskbar = $false

$img = $null
if ($Logo -and (Test-Path $Logo)) {
    $img = [System.Drawing.Image]::FromFile($Logo)
    $maxW = 760
    $scale = [Math]::Min(1.0, $maxW / $img.Width)
    $w = [int]($img.Width * $scale)
    $h = [int]($img.Height * $scale)
    $form.ClientSize = New-Object System.Drawing.Size ([Math]::Max($w + 24, 520)), ($h + 70)
    $pic = New-Object System.Windows.Forms.PictureBox
    $pic.Image = $img
    $pic.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    $pic.SetBounds(12, 12, $w, $h)
    $form.Controls.Add($pic)
} else {
    $form.ClientSize = New-Object System.Drawing.Size 520, 160
}

$label = New-Object System.Windows.Forms.Label
$label.Text = "Запуск FTDI/USB Logger…"
$label.ForeColor = [System.Drawing.Color]::FromArgb(210, 220, 230)
$label.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$label.SetBounds(12, $form.ClientSize.Height - 46, $form.ClientSize.Width - 24, 32)
$form.Controls.Add($label)

$script:done = $false
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 350
$timer.Add_Tick({
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task = $client.ConnectAsync("127.0.0.1", $Port)
        if ($task.Wait(150) -and $client.Connected) {
            $script:done = $true
            $timer.Stop()
            $form.Close()
        }
        $client.Close()
    } catch {}
})

$form.Add_Shown({
    $timer.Start()
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline -and -not $script:done) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 120
    }
    if (-not $script:done) {
        $label.Text = "Движок не ответил — смотрите logger.err.log"
        $close = New-Object System.Windows.Forms.Timer
        $close.Interval = 2500
        $close.Add_Tick({ $close.Stop(); $form.Close() })
        $close.Start()
        while ($form.Visible) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 }
    }
})

[void]$form.ShowDialog()
if ($img) { $img.Dispose() }
