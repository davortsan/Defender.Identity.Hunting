$tenantID = "3cdeeda9-1dec-46f0-90dc-261e76ea4e99"
$appID = "743c9212-cf83-4a35-a4be-bd9d73ef2099"
$appSecret = "W.s8Q~x1XO8d8QF1Gqg2xKiRXsl~F2IrO7pLsayS"
$resourceAppIdUri = 'https://graph.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token"

# Cuerpo de la solicitud
$body = [Ordered]@{
    resource = $resourceAppIdUri
    client_id = $appId
    client_secret = $appSecret
    grant_type = 'client_credentials'
}


# Obtener el token
$response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
$aadToken = $response.access_token

$url = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"

$headers = @{
    'Content-Type' = 'application/json'
    'Authorization' = "Bearer $aadToken"
}

#AD Group Additions
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for AD Group Additions" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
$query = "let Groups = dynamic(['Domain Admins','Enterprise Admins','SensitiveGroup1']); let SearchWindow = 24h; IdentityDirectoryEvents | where Timestamp > (now() - SearchWindow) | where ActionType == 'Group Membership changed' | extend Group = parse_json(AdditionalFields).['TO.GROUP'] | extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT'] | project-reorder Group, GroupAdditionInitiatedBy | where Group has_any (Groups)"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results." -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#COMENTADO A EXPENSAS DE REVISAR DE DONDE OBTIENE $left y $right
#Password Change after successfully brute force
#Write-Host "===============================================================" -ForegroundColor Green
#Write-Host "Hunting Query Results for Password Change after Brute Force" -ForegroundColor Green
#Write-Host "===============================================================" -ForegroundColor Green
##$query = "let FailedLogonsThreshold = 20; let SuccessfulLogonsThreshold = 1; let TimeWindow = 15m; let SearchWindow = 120; IdentityLogonEvents | where isnotempty(AccountUpn) | summarize TotalAttempts = count(), SuccessfulAttempts = countif(ActionType == 'LogonSuccess'), FailedAttempts = countif(ActionType == 'LogonFailed') by bin(TimeGenerated, TimeWindow), AccountUpn | where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold | join kind=inner (IdentityDirectoryEvents | where TimeGenerated > ago(30d) | where ActionType == 'Account Password changed' | where isnotempty(TargetAccountUpn) | extend PasswordChangeTime = TimeGenerated | project PasswordChangeTime, TargetAccountUpn) on $left.AccountUpn == $right.TargetAccountUpn | extend TimeDifference = datetime_diff('minute', PasswordChangeTime, TimeGenerated) | where TimeDifference > 0 | where TimeDifference <= SearchWindow"
#$body = ConvertTo-Json -InputObject @{ Query = $query }
#$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
#$results = ($response | ConvertFrom-Json).Results
#$results | Format-Table

#Detect malicious ISPs
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Malicious ISPs" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
$query = "IdentityLogonEvents | where Timestamp > ago(1d) | extend ISPRate = iif(FailureReason contains 'locked', 'Suspicious','valid') | where ISP !in ('vodafone btw ') and Location !in ('IT') | project ISP, Location, IPAddress, AccountDomain, LogonType, FailureReason, ISPRate | order by ISP"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results." -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Disabled user
Write-Host "===============================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Disabled user" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Account disabled' | project TimeGenerated, UserDisabled=TargetAccountDisplayName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results." -ForegroundColor Yellow
} else {
    $results | Format-Table
}