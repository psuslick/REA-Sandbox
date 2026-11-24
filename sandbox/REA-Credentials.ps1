# Guest-only WinForms credential dialog. No files, console echo, or automatic clipboard reads.
function Get-REACredentials {
    param([string]$InitialId = '')
    if ($env:USERNAME -ine 'WDAGUtilityAccount') { throw 'Credential dialog is guest-only.' }
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'REA-VM | Connect to OpenAI'
    $form.ClientSize = New-Object System.Drawing.Size(570, 305)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $heading = New-Object System.Windows.Forms.Label
    $heading.Text = 'Provisioning checks passed. Paste your existing REA-VM credentials.'
    $heading.SetBounds(18, 16, 532, 48)
    $idLabel = New-Object System.Windows.Forms.Label
    $idLabel.Text = 'Tunnel ID (tunnel_...)'
    $idLabel.SetBounds(18, 66, 532, 23)
    $idBox = New-Object System.Windows.Forms.TextBox
    $idBox.SetBounds(18, 92, 532, 30)
    $idBox.Text = $InitialId
    $idBox.MaxLength = 256
    $keyLabel = New-Object System.Windows.Forms.Label
    $keyLabel.Text = 'Restricted runtime API key (Tunnels Read + Use)'
    $keyLabel.SetBounds(18, 132, 532, 23)
    $keyBox = New-Object System.Windows.Forms.TextBox
    $keyBox.SetBounds(18, 158, 532, 30)
    $keyBox.UseSystemPasswordChar = $true
    $keyBox.MaxLength = 4096
    $note = New-Object System.Windows.Forms.Label
    $note.Text = 'Use Ctrl+V in each field. Never use the HA-MCP ID or an admin key. Clear your host clipboard after connecting.'
    $note.SetBounds(18, 200, 532, 52)
    $connect = New-Object System.Windows.Forms.Button
    $connect.Text = 'Connect'
    $connect.SetBounds(340, 262, 102, 32)
    $connect.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.SetBounds(448, 262, 102, 32)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $connect
    $form.CancelButton = $cancel
    $form.Controls.AddRange([System.Windows.Forms.Control[]]@($heading,$idLabel,$idBox,$keyLabel,$keyBox,$note,$connect,$cancel))
    try {
        while ($true) {
            $form.ActiveControl = if ($idBox.TextLength) { $keyBox } else { $idBox }
            if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
            $id = $idBox.Text.Trim()
            $key = $keyBox.Text.Trim()
            if ($id -match '^tunnel_[A-Za-z0-9_-]{12,128}$' -and $key -match '^sk-[A-Za-z0-9_-]{8,}$') {
                return [pscustomobject]@{Id=$id;Key=$key}
            }
            $key = $null
            $keyBox.Clear()
            [void][System.Windows.Forms.MessageBox]::Show('Check the tunnel ID and runtime key format. Neither was logged. Paste the corrected values and try again.', 'Check credentials', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    } finally {
        $key = $null
        $keyBox.Clear()
        $form.Dispose()
    }
}
