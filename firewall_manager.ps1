param()

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Administrator-Rechte erforderlich. Starte Skript als Administrator..." -ForegroundColor Yellow
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if ($scriptPath) {
            $pwshPath = Get-Command "pwsh.exe" -ErrorAction SilentlyContinue
            if ($pwshPath) {
                Write-Host "Verwende PowerShell 7..." -ForegroundColor Green
                Start-Process -FilePath "pwsh.exe" -ArgumentList "-NoExit", "-File", "`"$scriptPath`"" -Verb RunAs
            } else {
                Write-Host "PowerShell 7 nicht gefunden, verwende Windows PowerShell..." -ForegroundColor Yellow
                Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-File", "`"$scriptPath`"" -Verb RunAs
            }
            exit 0
        } else {
            Write-Host "Fehler: Skript-Pfad konnte nicht ermittelt werden." -ForegroundColor Red
            Read-Host "Druecke Enter zum Beenden"
            exit 1
        }
    }
    catch {
        Write-Host "Fehler beim Starten als Administrator: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host "Druecke Enter zum Beenden"
        exit 1
    }
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    $FormsAvailable = $true
}
catch {
    Write-Host "Windows Forms nicht verfuegbar - Ordner-Dialog deaktiviert" -ForegroundColor Yellow
    $FormsAvailable = $false
}

$RULE_PREFIX = "PSFirewallBlock_"

function Show-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host "  |                                                              |" -ForegroundColor Magenta
    Write-Host "  |                    FIREWALL MANAGER                         |" -ForegroundColor Magenta
    Write-Host "  |                                                              |" -ForegroundColor Magenta
    Write-Host "  |               PowerShell Edition v2.0                       |" -ForegroundColor Magenta
    Write-Host "  |                                                              |" -ForegroundColor Magenta
    Write-Host "  ================================================================" -ForegroundColor Magenta
    Write-Host ""
}

function Show-Menu {
    Show-Header
    
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  |                       HAUPTMENUE                            |" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "    1 - .exe Dateien blockieren" -ForegroundColor Green
    Write-Host "    2 - Erstellte Regeln anzeigen" -ForegroundColor Green  
    Write-Host "    3 - Regeln entfernen" -ForegroundColor Green
    Write-Host "    4 - Beenden" -ForegroundColor Red
    
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Waehle eine Option (1-4): " -ForegroundColor Yellow -NoNewline
}

function Show-Section {
    param([string]$title)
    
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
}

function Block-ExeFiles {
    Show-Section "EXE DATEIEN BLOCKIEREN"
    
    Write-Host "  Wie moechtest du den Ordner auswaehlen?" -ForegroundColor Yellow
    Write-Host ""
    
    if ($FormsAvailable) {
        Write-Host "    1 - Ordner-Dialog (empfohlen)" -ForegroundColor Cyan
        Write-Host "    2 - Pfad manuell eingeben" -ForegroundColor Cyan
    } else {
        Write-Host "    2 - Pfad manuell eingeben" -ForegroundColor Cyan
    }
    
    Write-Host ""
    $pathChoice = Read-Host "  Auswahl"
    $folderPath = ""
    
    if ($pathChoice -eq "1" -and $FormsAvailable) {
        Write-Host ""
        Write-Host "  Oeffne Ordner-Dialog..." -ForegroundColor Yellow
        
        try {
            $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
            $folderBrowser.Description = "Waehle den Ordner aus, in dem alle .exe Dateien blockiert werden sollen"
            $folderBrowser.RootFolder = [System.Environment+SpecialFolder]::MyComputer
            $folderBrowser.ShowNewFolderButton = $false
            
            $result = $folderBrowser.ShowDialog()
            
            if ($result -eq [System.Windows.Forms.DialogResult]::Cancel -or [string]::IsNullOrEmpty($folderBrowser.SelectedPath)) {
                Write-Host "  Vorgang abgebrochen" -ForegroundColor Red
                Read-Host "  Enter druecken..."
                return
            }
            
            $folderPath = $folderBrowser.SelectedPath
            Write-Host "  Ordner: " -ForegroundColor Green -NoNewline
            Write-Host "$folderPath" -ForegroundColor White
        }
        catch {
            Write-Host "  Dialog-Fehler - wechsle zu manueller Eingabe" -ForegroundColor Red
            $folderPath = Read-Host "  Pfad eingeben"
        }
    } elseif ($pathChoice -eq "2" -or (-not $FormsAvailable)) {
        $folderPath = Read-Host "`n  Vollstaendigen Pfad eingeben"
    } else {
        Write-Host "  Ungueltige Auswahl!" -ForegroundColor Red
        Read-Host "  Enter druecken..."
        return
    }
    
    if (-not (Test-Path -Path $folderPath)) {
        Write-Host "  Pfad existiert nicht: $folderPath" -ForegroundColor Red
        Read-Host "  Enter druecken..."
        return
    }
    
    Write-Host ""
    Write-Host "  Durchsuche Ordner nach .exe Dateien..." -ForegroundColor Yellow
    $exeFiles = Get-ChildItem -Path $folderPath -Filter "*.exe" -Recurse -File
    
    if ($exeFiles.Count -eq 0) {
        Write-Host "  Keine .exe Dateien gefunden!" -ForegroundColor Yellow
        Read-Host "  Enter druecken..."
        return
    }
    
    Write-Host "  Gefunden: " -ForegroundColor Green -NoNewline
    Write-Host "$($exeFiles.Count) .exe Datei(en)" -ForegroundColor White
    Write-Host ""
    
    $confirm = Read-Host "  Alle gefundenen Dateien blockieren? (j/N)"
    if ($confirm -ne 'j' -and $confirm -ne 'J') {
        Write-Host "  Vorgang abgebrochen" -ForegroundColor Yellow
        Read-Host "  Enter druecken..."
        return
    }
    
    Write-Host ""
    Write-Host "  Erstelle Firewall-Regeln..." -ForegroundColor Cyan
    Write-Host ""
    
    $successCount = 0
    $errorCount = 0
    
    foreach ($exe in $exeFiles) {
        $fileName = $exe.Name
        $fullPath = $exe.FullName
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        
        Write-Host "    Blockiere: " -ForegroundColor White -NoNewline
        Write-Host "$fileName" -ForegroundColor Cyan -NoNewline
        
        try {
            $inboundRuleName = "$RULE_PREFIX$baseName" + "_Inbound"
            New-NetFirewallRule -DisplayName $inboundRuleName -Direction Inbound -Program $fullPath -Action Block -Enabled True | Out-Null
            
            $outboundRuleName = "$RULE_PREFIX$baseName" + "_Outbound"
            New-NetFirewallRule -DisplayName $outboundRuleName -Direction Outbound -Program $fullPath -Action Block -Enabled True | Out-Null
            
            $successCount++
            Write-Host " [OK]" -ForegroundColor Green
        }
        catch {
            $errorCount++
            Write-Host " [FEHLER]" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "  ZUSAMMENFASSUNG:" -ForegroundColor Magenta
    Write-Host "  Erfolgreich: $successCount Datei(en)" -ForegroundColor Green
    if ($errorCount -gt 0) {
        Write-Host "  Fehler: $errorCount Datei(en)" -ForegroundColor Red
    }
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Magenta
    
    Read-Host "`n  Enter druecken..."
}

function Show-CreatedRules {
    Show-Section "ERSTELLTE FIREWALL-REGELN"
    
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$RULE_PREFIX*" }
    
    if ($rules.Count -eq 0) {
        Write-Host "  Keine Regeln durch dieses Tool gefunden" -ForegroundColor Yellow
        Read-Host "  Enter druecken..."
        return
    }
    
    Write-Host "  Gefundene Regeln: " -ForegroundColor Green -NoNewline
    Write-Host "$($rules.Count)" -ForegroundColor White
    Write-Host ""
    
    $groupedRules = $rules | Group-Object { 
        $appInfo = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_
        $appInfo.Program 
    }
    
    foreach ($group in $groupedRules) {
        $program = $group.Name
        $programName = Split-Path -Leaf $program
        
        Write-Host "  ------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Programm: " -ForegroundColor White -NoNewline
        Write-Host "$programName" -ForegroundColor Cyan
        Write-Host "  Pfad: $program" -ForegroundColor Gray
        
        foreach ($rule in $group.Group) {
            $direction = if ($rule.Direction -eq "Inbound") { "Eingehend" } else { "Ausgehend" }
            $status = if ($rule.Enabled -eq "True") { "Aktiv" } else { "Inaktiv" }
            $statusColor = if ($rule.Enabled -eq "True") { "Green" } else { "Red" }
            
            Write-Host "    $direction - " -ForegroundColor White -NoNewline
            Write-Host "$status" -ForegroundColor $statusColor
        }
        Write-Host ""
    }
    
    Read-Host "  Enter druecken..."
}

function Remove-CreatedRules {
    Show-Section "FIREWALL-REGELN ENTFERNEN"
    
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$RULE_PREFIX*" }
    
    if ($rules.Count -eq 0) {
        Write-Host "  Keine Regeln zum Entfernen gefunden" -ForegroundColor Yellow
        Read-Host "  Enter druecken..."
        return
    }
    
    $groupedRules = $rules | Group-Object { 
        $appInfo = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_
        $appInfo.Program 
    }
    
    Write-Host "  Verfuegbare Programme:" -ForegroundColor Green
    Write-Host ""
    
    $programs = @()
    $index = 1
    foreach ($group in $groupedRules) {
        $program = $group.Name
        $programName = Split-Path -Leaf $program
        $ruleCount = $group.Group.Count
        
        Write-Host "    $index - $programName " -ForegroundColor Cyan -NoNewline
        Write-Host "($ruleCount Regeln)" -ForegroundColor Gray
        
        $programs += @{
            Index = $index
            Program = $program
            ProgramName = $programName
            Rules = $group.Group
        }
        $index++
    }
    
    Write-Host ""
    Write-Host "    A - ALLE Regeln entfernen" -ForegroundColor Red
    Write-Host "    0 - Zurueck" -ForegroundColor Yellow
    
    Write-Host ""
    $choice = Read-Host "  Auswahl"
    
    if ($choice -eq "0") {
        return
    } elseif ($choice.ToUpper() -eq "A") {
        Write-Host ""
        Write-Host "  WARNUNG: Alle Regeln werden entfernt!" -ForegroundColor Red
        $confirm = Read-Host "  Wirklich fortfahren? (j/N)"
        
        if ($confirm -eq 'j' -or $confirm -eq 'J') {
            Remove-RulesByList -rules $rules -description "alle Programme"
        } else {
            Write-Host "  Abgebrochen" -ForegroundColor Yellow
        }
    } else {
        $selectedIndex = $null
        if ([int]::TryParse($choice, [ref]$selectedIndex) -and $selectedIndex -ge 1 -and $selectedIndex -le $programs.Count) {
            $selectedProgram = $programs[$selectedIndex - 1]
            
            Write-Host ""
            Write-Host "  Regeln fuer '$($selectedProgram.ProgramName)' entfernen?" -ForegroundColor Yellow
            $confirm = Read-Host "  Bestaetigen (j/N)"
            
            if ($confirm -eq 'j' -or $confirm -eq 'J') {
                Remove-RulesByList -rules $selectedProgram.Rules -description $selectedProgram.ProgramName
            } else {
                Write-Host "  Abgebrochen" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  Ungueltige Auswahl!" -ForegroundColor Red
        }
    }
    
    Read-Host "`n  Enter druecken..."
}

function Remove-RulesByList {
    param(
        [Parameter(Mandatory=$true)]
        $rules,
        [Parameter(Mandatory=$true)]
        [string]$description
    )
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "  Entferne Regeln fuer: $description" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($rule in $rules) {
        Write-Host "    Entferne: " -ForegroundColor White -NoNewline
        Write-Host "$($rule.DisplayName)" -ForegroundColor Cyan -NoNewline
        
        try {
            Remove-NetFirewallRule -Name $rule.Name
            $successCount++
            Write-Host " [OK]" -ForegroundColor Green
        }
        catch {
            $errorCount++
            Write-Host " [FEHLER]" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "  ERGEBNIS:" -ForegroundColor Magenta
    Write-Host "  Entfernt: $successCount" -ForegroundColor Green
    if ($errorCount -gt 0) {
        Write-Host "  Fehler: $errorCount" -ForegroundColor Red
    }
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Magenta
}

try {
    do {
        Show-Menu
        $choice = Read-Host
        
        if ($choice -eq "1") {
            Block-ExeFiles
        } elseif ($choice -eq "2") {
            Show-CreatedRules
        } elseif ($choice -eq "3") {
            Remove-CreatedRules
        } elseif ($choice -eq "4") {
            Clear-Host
            Write-Host ""
            Write-Host "  Auf Wiedersehen!" -ForegroundColor Green
            Write-Host ""
            exit 0
        } else {
            Write-Host ""
            Write-Host "  Ungueltige Auswahl! Waehle 1-4." -ForegroundColor Red
            Read-Host "  Enter druecken..."
        }
    } while ($true)
}
catch {
    Write-Host "Kritischer Fehler: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Enter zum Beenden"
    exit 1
}