$apiUrl = "https://8xxfaies7l.execute-api.eu-west-2.amazonaws.com/api/scan"
$headers = @{ "x-api-token" = "secret-scanner-token-2283" }

$results = @()
Write-Host "Executing 30-Run Latency Benchmark (with 3s cooldown)..." -ForegroundColor Cyan

for ($i = 1; $i -le 30; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $type = if ($i -eq 1) { "Cold Start" } else { "Warm Start" }
    
    try {
        $res = Invoke-RestMethod -Uri $apiUrl -Method GET -Headers $headers -TimeoutSec 45
        $sw.Stop()
        $elapsed = $sw.ElapsedMilliseconds
        $count = $res.findings.Count
        $status = "Success"
        
        Write-Host "Iteration #$i ($type): $elapsed ms | Findings: $count" -ForegroundColor Green
    }
    catch {
        $sw.Stop()
        $elapsed = $sw.ElapsedMilliseconds
        $count = 0
        $status = "Gateway Timeout / 503"
        
        Write-Host "Iteration #$i ($type): $elapsed ms | Error: Gateway Timeout" -ForegroundColor Red
    }
    
    $results += [PSCustomObject]@{
        Iteration     = $i
        ExecutionType = $type
        Status        = $status
        LatencyMs     = $elapsed
        AssetsCount   = $count
    }
    
    # 3-second cooldown to let AWS API rate limits reset
    Start-Sleep -Seconds 3
}

$results | Export-Csv -Path ".\latency_benchmark_30_runs.csv" -NoTypeInformation
Write-Host "Benchmark Complete! Saved to latency_benchmark_30_runs.csv" -ForegroundColor Green