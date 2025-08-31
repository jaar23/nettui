import std/[times, strformat, strutils, os, sequtils, tables, tasks, json]
import tui_widget
import ./network_monitor

type
  AppState = ref object
    connections: seq[SocketInfo]
    stats: NetworkStats
    lastUpdate: DateTime
    selectedIndex: int
    autoRefresh: bool
    connectionTable: tui_widget.Table
    statsDisplay: Display
    detailDisplay: Display
    statusLabel: Label

var
  prevUpdateTime: DateTime
  prevBytesSent: tables.Table[int, int64] 
  prevBytesReceived: tables.Table[int, int64]

var totalBytesSent: ChartData = @[]
var totalBytesReceived: ChartData = @[]

proc calculateSpeed(currentBytes, prevBytes: int64, timeDelta: float): string =
  ## Calculate speed in KB/s
  if timeDelta <= 0 or prevBytes == 0:
    return "0.0 KB/s"
  
  let bytesDelta = currentBytes - prevBytes
  if bytesDelta <= 0:
    return "0.0 KB/s"
  
  let kbPerSecond = (bytesDelta.float / 1024.0) / timeDelta
  result = fmt"{kbPerSecond:.1f} KB/s"

proc formatConnectionData(connections: seq[SocketInfo]): seq[seq[string]] =
  result = @[]
  for conn in connections:
    result.add(@[
      $conn.pid,
      conn.processName,
      conn.protocol,
      fmt"{conn.localAddress}:{conn.localPort}",
      fmt"{conn.remoteAddress}:{conn.remotePort}",
      conn.state,
      formatBytes(conn.bytesSent),
      formatBytes(conn.bytesReceived)
    ])


let updateNetworkData = proc(appPtr: ptr TerminalApp, id: string) {.gcsafe.} =
  while true:
    let networkDataStr = getUpdate()

    notify(appPtr, id, "network-update", networkDataStr)
    sleep(3000)

proc main() =
  var state = AppState(
    connections: @[],
    stats: NetworkStats(),
    lastUpdate: now(),
    selectedIndex: 0,
    autoRefresh: false
  )

  # Initialize the app
  var app = newTerminalApp(title="Network Monitor", border=false, rpms=100)
  
  var tcpConnCount = newLabel(id="tcp-connection")
  tcpConnCount.text = "TCP: N/A" 
  tcpConnCount.bg(bgBlue) 
  tcpConnCount.fg(fgBlack)
  tcpConnCount.align = Center
  tcpConnCount.border = true

  var udpConnCount = newLabel(id="udp-connection")
  udpConnCount.text = "UDP: N/A" 
  udpConnCount.bg(bgGreen) 
  udpConnCount.fg(fgBlack)
  udpConnCount.align = Center
  udpConnCount.border = true

  var bsChart = newChart(id="bytes-sent-chart")
  bsChart.border = true
  bsChart.title = "Total Bytes Sent (Mb)"
  bsChart.chartType = BarChart
  bsChart.setData(totalBytesSent)
  bsChart.showGrid = true
  bsChart.showLabels = true
  bsChart.showValues = true

  var brChart = newChart(id="bytes-recv-chart")
  brChart.border = true
  brChart.title = "Total Bytes Received (Mb)"
  brChart.chartType = BarChart
  brChart.setData(totalBytesReceived)
  brChart.showGrid = true
  brChart.showLabels = true
  brChart.showValues = true

  # Create connection table
  const header = @["PID", "Process", "Protocol", "Local", "Remote", "State", "Sent", "Received"]
  var connectionTable = newTable(
    1, 1,
    consoleWidth(),
    consoleHeight(),
    id="network-data-table",
    title="Network Connections",
    statusbar=false
  )
  connectionTable.headerFromArray(header)
  
  connectionTable.on("network-update", proc(tb: tui_widget.Table, args: varargs[string]) =
    # parse the json string into to network json object
    # 
    #  {
    # "timestamp": now().toUnix(),
    # "network_stats": {
    #   "total_bytes_sent": networkStats.totalBytesSent,
    #   "total_bytes_received": networkStats.totalBytesReceived,
    #   "active_connections": networkStats.activeConnections,
    #   "tcp_connections": networkStats.tcpConnections,
    #   "udp_connections": networkStats.udpConnections,
    #   "connections_by_state": networkStats.connectionsByState
    # },
    #   "socket_info": []
    # }
    try:
      let networkObject = parseJson(args[0])
      let currentTime = now()
      let timeDelta = if prevUpdateTime.isInitialized: 
                        (currentTime - prevUpdateTime).inSeconds.float 
                      else: 3.0  # Default to 3 seconds if first update
      
      var socketData = newSeq[seq[string]]()
      var currentBytesSent = initTable[int, int64]()
      var currentBytesReceived = initTable[int, int64]()
      
      let tcpConn = networkObject["network_stats"]["tcp_connections"].getInt()
      tcpConnCount.text = if tcpConn > 0: fmt"TCP: {tcpConn}" else: "TCP: 0"

      let udpConn = networkObject["network_stats"]["udp_connections"].getInt()
      udpConnCount.text = if tcpConn > 0: fmt"UDP: {udpConn}" else: "UDP: 0"

      let totalBytesSent = networkObject["network_stats"]["total_bytes_sent"].getFloat()
      let newPoint = DataPoint(label: $currentTime.format("HH:mm:ss"), value: totalBytesSent / 1024000.0)
      bsChart.addDataPoint(newPoint.label, newPoint.value)

      let totalBytesReceived = networkObject["network_stats"]["total_bytes_received"].getFloat()
      let newPoint2 = DataPoint(label: $currentTime.format("HH:mm:ss"), value: totalBytesReceived / 1024000.0)
      brChart.addDataPoint(newPoint2.label, newPoint2.value)

      for soc in networkObject["socket_info"]:        
        let pid = soc["pid"].getInt()
        let bytesSent = soc["bytes_sent"].getInt()
        let bytesReceived = soc["bytes_received"].getInt()
        
        # Store current values for next calculation
        currentBytesSent[pid] = bytesSent
        currentBytesReceived[pid] = bytesReceived
        
        # Calculate speeds
        let sentSpeed = if prevBytesSent.hasKey(pid):
                        calculateSpeed(bytesSent, prevBytesSent[pid], timeDelta)
                      else:
                        "0.0 KB/s"
        
        let receivedSpeed = if prevBytesReceived.hasKey(pid):
                            calculateSpeed(bytesReceived, prevBytesReceived[pid], timeDelta)
                          else:
                            "0.0 KB/s"
        
        let row = @[
          $pid, 
          soc["process_name"].getStr(), 
          soc["protocol"].getStr(), 
          soc["local_address"].getStr() & ":" & $soc["local_port"].getInt(), 
          soc["remote_address"].getStr() & ":" & $soc["remote_port"].getInt(),
          soc["state"].getStr(),
          sentSpeed,  # Changed from total bytes to speed
          receivedSpeed  # Changed from total bytes to speed
        ]

        if tb.filteredValue != "":
          for col in row:
            if tb.filteredValue in col:
              socketData.add(row)
        else:
          socketData.add(row)
      
      # Update previous values for next calculation
      prevBytesSent = currentBytesSent
      prevBytesReceived = currentBytesReceived
      prevUpdateTime = currentTime
      
      tb.clearRows()
      tb.loadFromSeq(socketData)
    except:
      echo getCurrentExceptionMsg()
      quit(-1)
  )

  let updateNetworkDataTask = toTask updateNetworkData(addr app, connectionTable.id)
  runInBackground(updateNetworkDataTask)

  # Add widgets to app
  app.addWidget(tcpConnCount, 0.5, 0.05)
  app.addWidget(udpConnCount, 0.5, 0.05)
  app.addWidget(bsChart, 0.5, 0.3)
  app.addWidget(brChart, 0.5, 0.3)
  app.addWidget(connectionTable, 1.0, 0.55, 0, 1, 0, 0)

 
  # Run the app
  app.run(nonBlocking=true)

when isMainModule:
  main()