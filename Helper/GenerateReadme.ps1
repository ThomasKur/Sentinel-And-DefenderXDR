$RepoRawUrl             = "https://raw.githubusercontent.com/ThomasKur/Sentinel-And-DefenderXDR/main"
$RepoUrl                = "https://github.com/ThomasKur/Sentinel-And-DefenderXDR/blob/main"
$MainReadmeTemplate     = Get-Content -Path .\Helper\Templates\Main-Readme.md

#region LogicApp / Extend
$MainReadmeTableLaExt   = "| Name | Description | Deploy |" + [System.Environment]::NewLine
$MainReadmeTableLaExt  += "| --- | --- | --- |" + [System.Environment]::NewLine

$bicepLaExtFiles        = Get-ChildItem -Path .\LogicApps\Extend -Recurse -Filter "*.bicep"

foreach($bicepLaExtFile in $bicepLaExtFiles){
    $Content            = Get-Content -Path $bicepLaExtFile.PSPath
    $Title              = ($Content | Where-Object { $_.StartsWith('// Title: ')}).Replace("// Title: ","")
    $TitleLink          = "[$Title](" + $RepoUrl + $bicepLaExtFile.PSParentPath.Replace((Get-Location).Path,"").Replace("\","/").Replace("Microsoft.PowerShell.Core/FileSystem::","") + "/Readme.md)"
    $Description        = ($Content | Where-Object { $_.StartsWith('// Description: ')}).Replace("// Description: ","")
    $GraphScopes        = ($Content | Where-Object { $_.StartsWith('// GraphScopes: ')}).Replace("// GraphScopes: ","")
    $RawUrlBicep        = $RepoRawUrl + $bicepLaExtFile.FullName.Replace((Get-Location).Path,"").Replace("\","/")
    $RawUrlArm          = $RawUrlBicep.Replace("bicep","json")
    $AzDeployLink       = "https://portal.azure.com/#create/Microsoft.Template/uri/" + [uri]::EscapeDataString($RawUrlArm)
    $AzDeployButton     = "[![Deploy to Azure](https://aka.ms/deploytoazurebutton)]($AzDeployLink)"
    
    # Generate Logic App Readme
    $template           = Get-Content -Path .\Helper\Templates\LogicApp-Extend-Readme.md
    $template           = $template.Replace("%Title%",$Title)
    $template           = $template.Replace("%Description%",$Description)
    $template           = $template.Replace("%GraphScopes%",$GraphScopes)
    $template           = $template.Replace("%RawUrlBicep%",$RawUrlBicep)
    $template           = $template.Replace("%AzDeployButton%",$AzDeployButton)

    $template | Out-File -FilePath "$($bicepLaExtFile.PSParentPath)\Readme.md" -Force

    $MainReadmeTableLaExt  += "| $TitleLink | $Description | $AzDeployButton |" + [System.Environment]::NewLine

}

$MainReadmeTemplate = $MainReadmeTemplate.Replace("%MainReadmeTableLaExt%",$MainReadmeTableLaExt)

#endregion

#region Detections

$MainReadmeTableDetections   = "| Name | Category |" + [System.Environment]::NewLine
$MainReadmeTableDetections  += "| --- | --- |" + [System.Environment]::NewLine

$DetectionFolders = Get-ChildItem -Path .\Detections -Directory

foreach($DetectionFolder in $DetectionFolders){
    $DetectionFiles = Get-ChildItem -Path $DetectionFolder.FullName -Filter "*.md"
    
    foreach($DetectionFile in $DetectionFiles){
        $Title          = $DetectionFile.BaseName
        $TitleLink      = "[$Title](" + $RepoUrl + $DetectionFile.FullName.Replace((Get-Location).Path,"").Replace("\","/") + ")"
        $Category       = $DetectionFolder.Name
        
        $MainReadmeTableDetections  += "| $TitleLink | $Category |" + [System.Environment]::NewLine
    }
}

$MainReadmeTemplate = $MainReadmeTemplate.Replace("%MainReadmeTableDetections%",$MainReadmeTableDetections)

#endregion

#region Finalizing

$MainReadmeTemplate | Out-File -FilePath "Readme.md" -Force

#endregion
