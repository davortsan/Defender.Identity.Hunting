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
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for AD Group Additions" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let Groups = dynamic(['Domain Admins','Enterprise Admins','SensitiveGroup1']); let SearchWindow = 24h; IdentityDirectoryEvents | where Timestamp > (now() - SearchWindow) | where ActionType == 'Group Membership changed' | extend Group = parse_json(AdditionalFields).['TO.GROUP'] | extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT'] | project-reorder Group, GroupAdditionInitiatedBy | where Group has_any (Groups)"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#COMENTADO A EXPENSAS DE REVISAR DE DONDE OBTIENE $left y $right
#Password Change after successfully brute force
#Write-Host "===============================================================================" -ForegroundColor Green
#Write-Host "Hunting Query Results for Password Change after Brute Force" -ForegroundColor Green
#Write-Host "===============================================================================" -ForegroundColor Green
##$query = "let FailedLogonsThreshold = 20; let SuccessfulLogonsThreshold = 1; let TimeWindow = 15m; let SearchWindow = 120; IdentityLogonEvents | where isnotempty(AccountUpn) | summarize TotalAttempts = count(), SuccessfulAttempts = countif(ActionType == 'LogonSuccess'), FailedAttempts = countif(ActionType == 'LogonFailed') by bin(TimeGenerated, TimeWindow), AccountUpn | where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold | join kind=inner (IdentityDirectoryEvents | where TimeGenerated > ago(30d) | where ActionType == 'Account Password changed' | where isnotempty(TargetAccountUpn) | extend PasswordChangeTime = TimeGenerated | project PasswordChangeTime, TargetAccountUpn) on $left.AccountUpn == $right.TargetAccountUpn | extend TimeDifference = datetime_diff('minute', PasswordChangeTime, TimeGenerated) | where TimeDifference > 0 | where TimeDifference <= SearchWindow"
#$body = ConvertTo-Json -InputObject @{ Query = $query }
#$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
#$results = ($response | ConvertFrom-Json).Results
#$results | Format-Table

#Detect malicious ISPs
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Malicious ISPs" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityLogonEvents | where Timestamp > ago(1d) | extend ISPRate = iif(FailureReason contains 'locked', 'Suspicious','valid') | where ISP !in ('vodafone btw ') and Location !in ('IT') | project ISP, Location, IPAddress, AccountDomain, LogonType, FailureReason, ISPRate | order by ISP"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Disabled user
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Disabled user" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Account disabled' | project TimeGenerated, UserDisabled=TargetAccountDisplayName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Group changes
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Group Changes" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Group Membership changed' | extend ToGroup = tostring(AdditionalFields.['TO.GROUP']) | extend FromGroup = tostring(AdditionalFields.['FROM.GROUP']) | project TimeGenerated, Actor=AccountName, UserAdded=TargetAccountUpn, ToGroup, FromGroup "
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Lateral movement paths
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Lateral Movement Paths" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Potential lateral movement path identified' | summarize arg_max(TimeGenerated, *) by ReportId | summarize Count=count()by AccountUpn, DeviceName | sort by Count desc"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#OS version changes
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for OS version changes" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Device Operating System changed' | extend ['Previous OS Version'] = tostring(AdditionalFields.['FROM Device Operating System']) | extend ['Current OS Version'] = tostring(AdditionalFields.['TO Device Operating System'])| project TimeGenerated, TargetDeviceName, ['Previous OS Version'], ['Current OS Version']"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Summarized listing of LDAP clear text passwords
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for LDAP clear text passwords" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let firstIndexof = (input:string, lookup: string) { indexof(input, lookup, 0, -1) }; IdentityLogonEvents | where LogonType == 'LDAP cleartext' and ActionType == 'LogonSuccess' | extend DomainName = substring(DestinationDeviceName, firstIndexof(DestinationDeviceName, '.') + 1) | summarize NumberOfEntries=count()by LogonType, ActionType, AccountDisplayName, DomainName, AccountSid, IPAddress, DeviceName, DC = DestinationDeviceName | sort by AccountDisplayName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Find which devices have been accessed by a compromised device and which protocol was used to connect
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for devices accessed by a compromised device" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let firstIndexof = (input:string, lookup: string) { indexof(input, lookup, 0, -1) }; IdentityLogonEvents | where LogonType == 'LDAP cleartext' and ActionType == 'LogonSuccess' | extend DomainName = substring(DestinationDeviceName, firstIndexof(DestinationDeviceName, '.') + 1) | summarize NumberOfEntries=count()by LogonType, ActionType, AccountDisplayName, DomainName, AccountSid, IPAddress, DeviceName, DC = DestinationDeviceName | sort by AccountDisplayName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Unused service accounts
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for unused service accounts" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let timeframe = 30d; let srvc_list = dynamic(['svc_account1@contoso.com','svc_account2@contoso.com','svc_account3@contoso.com','svc_account4@contoso.com','svc_account5@contoso.com','svc_account6@contoso.com']); IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn in~ (srvc_list) | summarize Count = count() by AccountName, DeviceName, Protocol"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Count Authentication Service Accounts
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Authentication Service Accounts" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let timeframe = 30d; let srvc_list = dynamic(['svc_account1@contoso.com','svc_account2@contoso.com','svc_account3@contoso.com','svc_account4@contoso.com','svc_account5@contoso.com','svc_account6@contoso.com']); IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn in~ (srvc_list) | summarize Count = count() by bin(Timestamp, 24h), AccountName, DeviceName | sort by Timestamp desc"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Visualize where service account is logon to
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for visualization where service account is logon to" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let timeframe = 30d; IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn startswith 'srvcSQL' or AccountUpn startswith 'svc_sql' | summarize Count = count() by AccountName, DeviceName | where Count > 50"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Anomalies in Kerberos TGS
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Kerberos TGS anomalies" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let starttime = 14d; let endtime = 1d; let timeframe = 1h; let TotalEventsThreshold = 3; let TimeSeriesData = IdentityLogonEvents | where Timestamp between (startofday(ago(starttime))..startofday(ago(endtime))) | make-series PerHourCount=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by AccountName; let TimeSeriesAlerts=TimeSeriesData | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit') | mv-expand PerHourCount to typeof(double), Timestamp to typeof(datetime), anomalies to typeof(double),score to typeof(double), baseline to typeof(long) | where anomalies > 0 | project AccountName, Timestamp, PerHourCount, baseline, anomalies, score | where PerHourCount > TotalEventsThreshold; TimeSeriesAlerts | join ( IdentityLogonEvents | where AdditionalFields has 'TARGET_OBJECT.USER' | extend ParsedFields = parse_json(AdditionalFields) | extend Spns = ParsedFields.Spns | extend TargetAccountDisplayName = ParsedFields.TargetAccountDisplayName | summarize UserSpnCount=count(),Spns=make_set(Spns), TargetAccountDisplayName=make_set(TargetAccountDisplayName) by AccountName, bin(Timestamp, 1h) ) on AccountName, Timestamp | extend AnomalyTimeattheHour = Timestamp | where isnotempty(AccountName) | where Spns !has 'krbtgt/' | where TargetAccountDisplayName contains 'srvc' | project AnomalyTimeattheHour, AccountName, TargetAccountDisplayName, PerHourCount, UserSpnCount, Spns, baseline, anomalies , score | sort by AnomalyTimeattheHour desc"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Detect when an account has been changed for the password to never expire
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Password Never Expire Changes" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Account Password Never Expires changed' | extend AdditionalInfo = parse_json(AdditionalFields) | extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires'] | extend NewValue = AdditionalInfo.['TO Account Password Never Expires'] | where NewValue == true | project TimeGenerated, AccountName, AccountDomain, OriginalValue, NewValue, ReportId, DeviceName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Detect SMB File Copies
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for SMB File Copies" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let WhitelistedAccounts = dynamic(['account1', 'account2']); IdentityDirectoryEvents | where ActionType == 'SMB file copy' | where not(AccountName has_any (WhitelistedAccounts)) | extend SMBFileCopyCount = parse_json(AdditionalFields).Count, FilePath = parse_json(AdditionalFields).FilePath, FileName = parse_json(AdditionalFields).FileName | project-rename SourceDeviceName = DeviceName | project-reorder TimeGenerated, ActionType, SourceDeviceName, DestinationDeviceName, FilePath, FileName, SMBFileCopyCount"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Detect when a device performs group policy reconnaissance that has not been performed from that device in the last 30-days
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Group Policy Reconnaissance" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let PreviousActivity = materialize (IdentityQueryEvents | where TimeGenerated > ago(30d) | where QueryType == 'AllGroupPolicies' | summarize make_set(DeviceName) ); IdentityQueryEvents | where TimeGenerated > ago(1d) | where QueryType == 'AllGroupPolicies' | where not(DeviceName has_any(PreviousActivity))"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Top 100 users that have the most interactive sign ins
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Top 100 Interactive Sign Ins" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityLogonEvents | where LogonType == 'Interactive' | where isempty(FailureReason) | distinct AccountUpn, DeviceName | summarize TotalUniqueInteractiveSignIns = count() by AccountUpn | top 100 by TotalUniqueInteractiveSignIns | render columnchart with (title='Top 100 users that have the most interactive sign ins')"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Hunt for newly identified lateral movement paths to sensitive accounts
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Newly Identified Lateral Movement Paths" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Potential lateral movement path identified' | extend AdditionalInfo = parse_json(AdditionalFields) | extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT'] | extend FromAccount = AdditionalFields.['FROM.ACCOUNT'] | project TimeGenerated, LateralMovementPathToSensitiveAccount, FromAccount, DeviceName, AccountName, AccountDomain"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Find all the executed LDAP queries from a compromised device
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Executed LDAP Queries" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Potential lateral movement path identified' | extend AdditionalInfo = parse_json(AdditionalFields) | extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT'] | extend FromAccount = AdditionalFields.['FROM.ACCOUNT'] | project TimeGenerated, LateralMovementPathToSensitiveAccount, FromAccount, DeviceName, AccountName, AccountDomain"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Find which devices have been accessed by a compromised device and which protocol was used to connect
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Accessed Devices and Protocols" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let CompromisedDevice = 'laptop.contoso.com';let SearchWindow = 48h; //Customizable h = hours, d = days IdentityLogonEvents | where Timestamp > (now() - SearchWindow) | where DeviceName == CompromisedDevice | summarize TotalDevicesAccessed = dcount(DestinationDeviceName), DevicesAccessed = make_set(DestinationDeviceName), ProtocolsUsed = make_set(Protocol) by DeviceName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Find which devices have been accessed by a list of compromised accounts and which protocol was used to connect
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Accessed Devices and Protocols (Compromised Accounts)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "let ComprimsedUsers = dynamic(['user1', 'user2']); let SearchWindow = 48h; IdentityLogonEvents | where Timestamp > (now() - SearchWindow) | where AccountName has_any (ComprimsedUsers) | where isnotempty(TargetDeviceName) | where ActionType == 'LogonSuccess' | project Timestamp, AccountName, Protocol, TargetDeviceName"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Find accounts that have been deleted and by whom
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Deleted Accounts" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where ActionType == 'Account deleted' | extend parsed=parse_json(AdditionalFields) | extend ACTOR_ENTITY_USER = iff( isnull(AdditionalFields.['ACTOR.ENTITY_USER']), AdditionalFields.['ACTOR.ENTITY_USER'], AdditionalFields.['ACTOR.ENTITY_USER']) | extend ACTOR_ENTITY_USER = iff( isnull(ACTOR_ENTITY_USER), AdditionalFields.['ACTOR.ENTITY_USER'], ACTOR_ENTITY_USER) | project Timestamp, ActionType, TargetAccountUpn, AccountName, ACTOR_ENTITY_USER, AdditionalFields"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}

#Added to group
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "Hunting Query Results for Added to Group" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$query = "IdentityDirectoryEvents | where Application == 'Active Directory' | where ActionType == 'Group Membership changed' | extend parsed=parse_json(AdditionalFields) | extend INITIATED_BY = iff( isnull(AdditionalFields.['ACTOR.ACCOUNT']), AdditionalFields.['ACTOR.ACCOUNT'], AdditionalFields.['ACTOR.ACCOUNT']) | extend GROUP_CHANGED = iff( isnull(AdditionalFields.['TO.GROUP']), AdditionalFields.['TO.GROUP'], AdditionalFields.['TO.GROUP']) | where GROUP_CHANGED <> '' | extend GROUP_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.GROUP']), AdditionalFields.['TARGET_OBJECT.GROUP'], AdditionalFields.['TARGET_OBJECT.GROUP']) | extend USER_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.USER']), AdditionalFields.['TARGET_OBJECT.USER'], AdditionalFields.['TARGET_OBJECT.USER']) | extend DEVICE_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.DEVICE']), AdditionalFields.['TARGET_OBJECT.DEVICE'], AdditionalFields.['TARGET_OBJECT.DEVICE']) | project Timestamp, ActionType, INITIATED_BY, GROUP_CHANGED, GROUP_ADDED, USER_ADDED, DEVICE_ADDED,AdditionalFields"
$body = ConvertTo-Json -InputObject @{ Query = $query }
$response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
$results = ($response | ConvertFrom-Json).Results
if ($results.Length -eq 0) {
    Write-Host "No results" -ForegroundColor Yellow
} else {
    $results | Format-Table
}