$tenantID = "3cdeeda9-1dec-46f0-90dc-261e76ea4e99"
$appID = "743c9212-cf83-4a35-a4be-bd9d73ef2099"
$appSecret = "W.s8Q~x1XO8d8QF1Gqg2xKiRXsl~F2IrO7pLsayS"
$resourceAppIdUri = "https://api.securitycenter.microsoft.com"
$oAuthUri = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"

$body = @{
    scope = $resourceAppIdUri + "/.default"
    client_id = $appID
    client_secret = $appSecret
    grant_type = "client_credentials"
}

$response = Invoke-RestMethod -Uri $oAuthUri -Method Post -Body $body

$query = "IdentityLogonEvents | limit 10"
$url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"

$headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $($response.access_token)"
}

$body = @{ Query = $query} | ConvertTo-Json
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
$results = ($response.Content | ConvertFrom-Json).results

$results | Format-Table -AutoSize