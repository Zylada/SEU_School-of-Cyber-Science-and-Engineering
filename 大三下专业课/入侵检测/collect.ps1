# 设置输出文件名
$outputFile = "57123242_hw6.log"

# 定义要输出的各个部分，使用 Here-String 让脚本更清晰
$output = @"

========== 1. Date and Time ==========
$(Get-Date)

========== 2. OS Version ==========
$(Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer)

========== 3. Hardware Information (CPU & Memory) ==========
CPU Information:
$(Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List)

Memory Information:
$(Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object { "Total Physical Memory: $([math]::Round($_.Sum / 1GB, 2)) GB" })

========== 4. Uptime ==========
$(Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime)

========== 5. Services Information ==========
$(Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, Status | Format-Table -AutoSize)

========== 6. NIC Information ==========
$(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed | Format-List)

========== 7. Route Information ==========
$(Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize)

========== 8. ARP Information ==========
$(Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Format-Table -AutoSize)

========== 9. Process Information ==========
$(Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 50 Name, CPU, WorkingSet, Id | Format-Table -AutoSize)
"@

# 将收集到的所有信息保存到文件
$output | Out-File -FilePath $outputFile -Encoding UTF8

Write-Host "信息收集完成，已保存到 $outputFile"