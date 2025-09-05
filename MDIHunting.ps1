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


Write-Host "===============================================================================" -ForegroundColor Yellow
Write-Host "Microsoft Defender for Identity Hunting Queries" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Yellow

$titles = @("AD Group Additions...",
    "Malicious ISPs...",
    "Disabled user...",
    "Group changes...",
    "Lateral movement paths...",
    "OS version changes...",
    "LDAP clear text passwords...",
    "Devices accessed by a compromised device...",
    "Unused service accounts...",
    "Authentication Service Accounts...",
    "Identify where service account is logon to...",
    "Kerberos TGS anomalies...",
    "Password Never Expire Changes...",
    "SMB File Copies...",
    "Group Policy Reconnaissance...",
    "Top 100 Interactive Sign Ins...",
    "Newly Identified Lateral Movement Paths...",
    "Executed LDAP Queries from a Compromised Device...",
    "Accessed Devices and Protocols from a Compromised Device...",
    "Accessed Devices and Protocols from a list of Compromised Accounts...",
    "Deleted Accounts...",
    "Added to Group...",
    "Removed from Group...",
    "Moving User objects to different OUs...")

$queries = @("let Groups = dynamic(['Domain Admins','Enterprise Admins','SensitiveGroup1']); let SearchWindow = 24h; IdentityDirectoryEvents | where Timestamp > (now() - SearchWindow) | where ActionType == 'Group Membership changed' | extend Group = parse_json(AdditionalFields).['TO.GROUP'] | extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT'] | project-reorder Group, GroupAdditionInitiatedBy | where Group has_any (Groups)",
    "IdentityLogonEvents | where Timestamp > ago(1d) | extend ISPRate = iif(FailureReason contains 'locked', 'Suspicious','valid') | where ISP !in ('vodafone btw ') and Location !in ('IT') | project ISP, Location, IPAddress, AccountDomain, LogonType, FailureReason, ISPRate | order by ISP",
    "IdentityDirectoryEvents | where ActionType == 'Account disabled' | project TimeGenerated, UserDisabled=TargetAccountDisplayName",
    "IdentityDirectoryEvents | where ActionType == 'Group Membership changed' | extend ToGroup = tostring(AdditionalFields.['TO.GROUP']) | extend FromGroup = tostring(AdditionalFields.['FROM.GROUP']) | project TimeGenerated, Actor=AccountName, UserAdded=TargetAccountUpn, ToGroup, FromGroup",
    "IdentityDirectoryEvents | where ActionType == 'Potential lateral movement path identified' | summarize arg_max(TimeGenerated, *) by ReportId | summarize Count=count()by AccountUpn, DeviceName | sort by Count desc",
    "IdentityDirectoryEvents | where ActionType == 'Device Operating System changed' | extend ['Previous OS Version'] = tostring(AdditionalFields.['FROM Device Operating System']) | extend ['Current OS Version'] = tostring(AdditionalFields.['TO Device Operating System'])| project TimeGenerated, TargetDeviceName, ['Previous OS Version'], ['Current OS Version']",
    "let firstIndexof = (input:string, lookup: string) { indexof(input, lookup, 0, -1) }; IdentityLogonEvents | where LogonType == 'LDAP cleartext' and ActionType == 'LogonSuccess' | extend DomainName = substring(DestinationDeviceName, firstIndexof(DestinationDeviceName, '.') + 1) | summarize NumberOfEntries=count()by LogonType, ActionType, AccountDisplayName, DomainName, AccountSid, IPAddress, DeviceName, DC = DestinationDeviceName | sort by AccountDisplayName",
    "let CompromisedDevice = 'laptop.contoso.com'; let SearchWindow = 48h; IdentityLogonEvents | where TimeGenerated > (now() - SearchWindow) | where DeviceName == CompromisedDevice | summarize TotalDevicesAccessed = dcount(DestinationDeviceName), DevicesAccessed = make_set(DestinationDeviceName), ProtocolsUsed = make_set(Protocol) by DeviceName",
    "let timeframe = 30d; let srvc_list = dynamic(['svc_account1@contoso.com','svc_account2@contoso.com','svc_account3@contoso.com','svc_account4@contoso.com','svc_account5@contoso.com','svc_account6@contoso.com']); IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn in~ (srvc_list) | summarize Count = count() by AccountName, DeviceName, Protocol",
    "let timeframe = 30d; let srvc_list = dynamic(['svc_account1@contoso.com','svc_account2@contoso.com','svc_account3@contoso.com','svc_account4@contoso.com','svc_account5@contoso.com','svc_account6@contoso.com']); IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn in~ (srvc_list) | summarize Count = count() by bin(Timestamp, 24h), AccountName, DeviceName | sort by Timestamp desc",
    "let timeframe = 30d; IdentityLogonEvents | where Timestamp >= ago(timeframe) | where AccountUpn startswith 'srvcSQL' or AccountUpn startswith 'svc_sql' | summarize Count = count() by AccountName, DeviceName | where Count > 50",
    "let starttime = 14d; let endtime = 1d; let timeframe = 1h; let TotalEventsThreshold = 3; let TimeSeriesData = IdentityLogonEvents | where Timestamp between (startofday(ago(starttime))..startofday(ago(endtime))) | make-series PerHourCount=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by AccountName; let TimeSeriesAlerts=TimeSeriesData | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit') | mv-expand PerHourCount to typeof(double), Timestamp to typeof(datetime), anomalies to typeof(double),score to typeof(double), baseline to typeof(long) | where anomalies > 0 | project AccountName, Timestamp, PerHourCount, baseline, anomalies, score | where PerHourCount > TotalEventsThreshold; TimeSeriesAlerts | join ( IdentityLogonEvents | where AdditionalFields has 'TARGET_OBJECT.USER' | extend ParsedFields = parse_json(AdditionalFields) | extend Spns = ParsedFields.Spns | extend TargetAccountDisplayName = ParsedFields.TargetAccountDisplayName | summarize UserSpnCount=count(),Spns=make_set(Spns), TargetAccountDisplayName=make_set(TargetAccountDisplayName) by AccountName, bin(Timestamp, 1h) ) on AccountName, Timestamp | extend AnomalyTimeattheHour = Timestamp | where isnotempty(AccountName) | where Spns !has 'krbtgt/' | where TargetAccountDisplayName contains 'srvc' | project AnomalyTimeattheHour, AccountName, TargetAccountDisplayName, PerHourCount, UserSpnCount, Spns, baseline, anomalies , score | sort by AnomalyTimeattheHour desc",
    "IdentityDirectoryEvents | where ActionType == 'Account Password Never Expires changed' | extend AdditionalInfo = parse_json(AdditionalFields) | extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires'] | extend NewValue = AdditionalInfo.['TO Account Password Never Expires'] | where NewValue == true | project TimeGenerated, AccountName, AccountDomain, OriginalValue, NewValue, ReportId, DeviceName",
    "let WhitelistedAccounts = dynamic(['account1', 'account2']); IdentityDirectoryEvents | where ActionType == 'SMB file copy' | where not(AccountName has_any (WhitelistedAccounts)) | extend SMBFileCopyCount = parse_json(AdditionalFields).Count, FilePath = parse_json(AdditionalFields).FilePath, FileName = parse_json(AdditionalFields).FileName | project-rename SourceDeviceName = DeviceName | project-reorder TimeGenerated, ActionType, SourceDeviceName, DestinationDeviceName, FilePath, FileName, SMBFileCopyCount",
    "let PreviousActivity = materialize (IdentityQueryEvents | where TimeGenerated > ago(30d) | where QueryType == 'AllGroupPolicies' | summarize make_set(DeviceName) ); IdentityQueryEvents | where TimeGenerated > ago(1d) | where QueryType == 'AllGroupPolicies' | where not(DeviceName has_any(PreviousActivity))",
    "IdentityLogonEvents | where LogonType == 'Interactive' | where isempty(FailureReason) | distinct AccountUpn, DeviceName | summarize TotalUniqueInteractiveSignIns = count() by AccountUpn | top 100 by TotalUniqueInteractiveSignIns | render columnchart with (title='Top 100 users that have the most interactive sign ins')",
    "IdentityDirectoryEvents | where ActionType == 'Potential lateral movement path identified' | extend AdditionalInfo = parse_json(AdditionalFields) | extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT'] | extend FromAccount = AdditionalFields.['FROM.ACCOUNT'] | project TimeGenerated, LateralMovementPathToSensitiveAccount, FromAccount, DeviceName, AccountName, AccountDomain",
    "let CompromisedDevice = 'laptop1.com'; let SearchWindow = 48h; IdentityQueryEvents | where Timestamp > ago(SearchWindow) | where DeviceName == CompromisedDevice | where Protocol == 'Ldap' | project Timestamp, QueryType, Query, Protocol, DeviceName, DestinationDeviceName, TargetAccountUpn",
    "let CompromisedDevice = 'laptop.contoso.com'; let SearchWindow = 48h; IdentityLogonEvents | where Timestamp > (now() - SearchWindow) | where DeviceName == CompromisedDevice | summarize TotalDevicesAccessed = dcount(DestinationDeviceName), DevicesAccessed = make_set(DestinationDeviceName), ProtocolsUsed = make_set(Protocol) by DeviceName",
    "let ComprimsedUsers = dynamic(['user1', 'user2']); let SearchWindow = 48h; IdentityLogonEvents | where Timestamp > (now() - SearchWindow) | where AccountName has_any (ComprimsedUsers) | where isnotempty(TargetDeviceName) | where ActionType == 'LogonSuccess' | project Timestamp, AccountName, Protocol, TargetDeviceName",
    "IdentityDirectoryEvents | where ActionType == 'Account deleted' | extend parsed=parse_json(AdditionalFields) | extend ACTOR_ENTITY_USER = iff( isnull(AdditionalFields.['ACTOR.ENTITY_USER']), AdditionalFields.['ACTOR.ENTITY_USER'], AdditionalFields.['ACTOR.ENTITY_USER']) | extend ACTOR_ENTITY_USER = iff( isnull(ACTOR_ENTITY_USER), AdditionalFields.['ACTOR.ENTITY_USER'], ACTOR_ENTITY_USER) | project Timestamp, ActionType, TargetAccountUpn, AccountName, ACTOR_ENTITY_USER, AdditionalFields",
    "IdentityDirectoryEvents | where Application == 'Active Directory' | where ActionType == 'Group Membership changed' | extend parsed=parse_json(AdditionalFields) | extend INITIATED_BY = iff( isnull(AdditionalFields.['ACTOR.ACCOUNT']), AdditionalFields.['ACTOR.ACCOUNT'], AdditionalFields.['ACTOR.ACCOUNT']) | extend GROUP_CHANGED = iff( isnull(AdditionalFields.['TO.GROUP']), AdditionalFields.['TO.GROUP'], AdditionalFields.['TO.GROUP']) | where GROUP_CHANGED <> '' | extend GROUP_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.GROUP']), AdditionalFields.['TARGET_OBJECT.GROUP'], AdditionalFields.['TARGET_OBJECT.GROUP']) | extend USER_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.USER']), AdditionalFields.['TARGET_OBJECT.USER'], AdditionalFields.['TARGET_OBJECT.USER']) | extend DEVICE_ADDED = iff( isnull(AdditionalFields.['TARGET_OBJECT.DEVICE']), AdditionalFields.['TARGET_OBJECT.DEVICE'], AdditionalFields.['TARGET_OBJECT.DEVICE']) | project Timestamp, ActionType, INITIATED_BY, GROUP_CHANGED, GROUP_ADDED, USER_ADDED, DEVICE_ADDED,AdditionalFields",
    "IdentityDirectoryEvents | where Application == 'Active Directory' | where ActionType == 'Group Membership changed' | extend parsed=parse_json(AdditionalFields) | extend INITIATED_BY = iff( isnull(AdditionalFields.['ACTOR.ACCOUNT']), AdditionalFields.['ACTOR.ACCOUNT'], AdditionalFields.['ACTOR.ACCOUNT']) | extend GROUP_CHANGED = iff( isnull(AdditionalFields.['FROM.GROUP']), AdditionalFields.['FROM.GROUP'], AdditionalFields.['FROM.GROUP']) | where GROUP_CHANGED <> '' | extend GROUP_REMOVED = iff( isnull(AdditionalFields.['TARGET_OBJECT.GROUP']),  AdditionalFields.['TARGET_OBJECT.GROUP'], AdditionalFields.['TARGET_OBJECT.GROUP']) | extend USER_REMOVED = iff( isnull(AdditionalFields.['TARGET_OBJECT.USER']), AdditionalFields.['TARGET_OBJECT.USER'], AdditionalFields.['TARGET_OBJECT.USER']) | extend DEVICE_REMOVED = iff( isnull(AdditionalFields.['TARGET_OBJECT.DEVICE']), AdditionalFields.['TARGET_OBJECT.DEVICE'], AdditionalFields.['TARGET_OBJECT.DEVICE']) | project Timestamp, ActionType, INITIATED_BY, GROUP_CHANGED, GROUP_REMOVED, USER_REMOVED, DEVICE_REMOVED,AdditionalFields",
    "IdentityDirectoryEvents | where ActionType == 'Account Path changed' | extend parsed=parse_json(AdditionalFields) | extend FROM_Account_Path = iff( isnull(AdditionalFields.['FROM Account Path']), AdditionalFields.['FROM Account Path'], AdditionalFields.['FROM Account Path']) | extend TO_Account_Path = iff( isnull(AdditionalFields.['TO Account Path']), AdditionalFields.['TO Account Path'], AdditionalFields.['TO Account Path']) | extend INITIATED_BY = iff( isnull(AdditionalFields.['ACTOR.ENTITY_USER']), AdditionalFields.['ACTOR.ENTITY_USER'], AdditionalFields.['ACTOR.ENTITY_USER']) | extend Affected_User = iff( isnull(AdditionalFields.['TARGET_OBJECT.USER']), AdditionalFields.['TARGET_OBJECT.USER'], AdditionalFields.['TARGET_OBJECT.USER']) | where TargetDeviceName == '' | project Timestamp, ActionType, INITIATED_BY, Affected_User, FROM_Account_Path, TO_Account_Path, AdditionalFields")


for($i=0; $i -lt$titles.Length; $i++) {
    Write-Host $titles[$i] -ForegroundColor White -NoNewline
    $query = $queries[$i]
    $body = ConvertTo-Json -InputObject @{ Query = $query }
    $response = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body -ErrorAction Stop
    $results = ($response | ConvertFrom-Json).Results
    if ($results.Length -eq 0) {
        Write-Host " OK!" -ForegroundColor Green
    } else {
        Write-Host " ALERT!" -ForegroundColor Red
        $results | Format-Table

    }
}