import std/[times, strformat, strutils, os, sequtils, tables, tasks, json]
import tui_widget
import ./network_monitor
import octolog

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
var currProcBytesSent: ChartData = @[]
var currProcBytesReceived: ChartData = @[]
var selectedProcess = -1
var selectedProcessName = ""

# start logging
octologStart(fileName="/tmp/nettui")

proc calculateSpeed(currentBytes, prevBytes: int64, timeDelta: float): string =
  ## Calculate speed in KB/s
  if timeDelta <= 0 or prevBytes == 0:
    return "0.0 KB/s"
  
  let bytesDelta = currentBytes - prevBytes
  if bytesDelta <= 0:
    return "0.0 KB/s"
  
  let kbPerSecond = (bytesDelta.float / 1024.0) / timeDelta
  result = fmt"{kbPerSecond:.1f} KB/s"

proc calculateSpeedFloat(currentBytes, prevBytes: int64, timeDelta: float): float =
  ## Calculate speed in KB/s
  if timeDelta <= 0 or prevBytes == 0:
    return 0.0
  
  let bytesDelta = currentBytes - prevBytes
  if bytesDelta <= 0:
    return 0.0
  
  let kbPerSecond = (bytesDelta.float / 1024.0) / timeDelta
  result = kbPerSecond

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
    sleep(1000)

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

  var conntrackCount = newLabel(id="conntrack-connection")
  conntrackCount.text = "CONN: N/A" 
  conntrackCount.bg(bgYellow) 
  conntrackCount.fg(fgBlack)
  conntrackCount.align = Center
  conntrackCount.border = true

  var natCount = newLabel(id="nat-connection")
  natCount.text = "NAT: N/A" 
  natCount.bg(bgMagenta) 
  natCount.fg(fgBlack)
  natCount.align = Center
  natCount.border = true

  var bsChart = newChart(id="bytes-sent-chart")
  bsChart.border = true
  bsChart.title = "⬆️ Total Bytes Sent (Mb)"
  bsChart.chartType = BarChart
  bsChart.setData(totalBytesSent)
  bsChart.showGrid = false
  bsChart.showLabels = true
  bsChart.showValues = true
  bsChart.maxVisiblePoints = 9
  bsChart.statusbar = false

  var brChart = newChart(id="bytes-recv-chart")
  brChart.border = true
  brChart.title = "⬇️ Total Bytes Received (Mb)"
  brChart.chartType = BarChart
  brChart.setData(totalBytesReceived)
  brChart.showGrid = false
  brChart.showLabels = true
  brChart.showValues = true
  brChart.maxVisiblePoints = 9
  brChart.statusbar = false

  var selSentChart = newChart(id="selected-pid-bytes-sent-chart")
  selSentChart.border = true
  selSentChart.title = "⬆️ Total Bytes Sent (Kb/s)"
  selSentChart.chartType = LineChart
  selSentChart.setData(@[])
  selSentChart.showGrid = false
  selSentChart.showLabels = true
  selSentChart.showValues = true
  selSentChart.maxVisiblePoints = 9
  selSentChart.statusbar = false

  var selRecvChart = newChart(id="selected-pid-bytes-recv-chart")
  selRecvChart.border = true
  selRecvChart.title = "⬇️ Total Bytes Recv (Kb/s)"
  selRecvChart.chartType = LineChart
  selRecvChart.setData(@[])
  selRecvChart.showGrid = false
  selRecvChart.showLabels = true
  selRecvChart.showValues = true
  selRecvChart.maxVisiblePoints = 9
  selRecvChart.statusbar = false

  # Create connection table
  const header = @["PID", "Process", "Protocol", "Local", "Remote", "State", "Sent", "Received", "RTT(ms)", "Queue", "Retr", "ConnState", "NAT Src", "NAT Dst"]
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
      udpConnCount.text = if udpConn > 0: fmt"UDP: {udpConn}" else: "UDP: 0"

      let conntrackEntries = networkObject["network_stats"]["conntrack_entries"].getInt()
      conntrackCount.text = if conntrackEntries > 0: fmt"CONN: {conntrackEntries}" else: "CONN: 0"

      let natTranslations = networkObject["network_stats"]["nat_translations"].getInt()
      natCount.text = if natTranslations > 0: fmt"NAT: {natTranslations}" else: "NAT: 0"

      # if bsChart.data.len() > 99:
      #   bsChart.data.delete(0, 9)
      # if brChart.data.len() > 99:
      #   brChart.data.delete(0, 9)

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

        # Get additional fields
        let rtt = if soc.hasKey("rtt"): $soc["rtt"].getInt() else: "N/A"
        let txQueue = if soc.hasKey("tx_queue"): $soc["tx_queue"].getInt() else: "0"
        let rxQueue = if soc.hasKey("rx_queue"): $soc["rx_queue"].getInt() else: "0"
        let queueInfo = fmt"{txQueue}/{rxQueue}"

        # if selSentChart.data.len() > 99:
        #   selSentChart.data.delete(0, 9)
        # if selRecvChart.data.len() > 99:
        #   selRecvChart.data.delete(0, 9)

        if selectedProcess > -1 and selectedProcess == pid:
          let currKbSent = calculateSpeedFloat(bytesSent, prevBytesSent[pid], timeDelta)
          selSentChart.addDataPoint($currentTime.format("HH:mm:ss"), currKbSent)

          let currKbRecv = calculateSpeedFloat(bytesReceived, prevBytesReceived[pid], timeDelta)
          selRecvChart.addDataPoint($currentTime.format("HH:mm:ss"), currKbRecv)

        # octolog.info($soc)
        # Handle NAT fields that might be empty due to permissions
        let natSrcAddr = if soc.hasKey("nat_src_address"): soc["nat_src_address"].getStr() else: "n/a"
        let natDstAddr = if soc.hasKey("nat_dst_address"): soc["nat_dst_address"].getStr() else: "n/a"
        let natSrcPort = if soc.hasKey("nat_src_port") and soc["nat_src_port"].getInt() > 0: $soc["nat_src_port"].getInt() else: ""
        let natDstPort = if soc.hasKey("nat_dst_port") and soc["nat_dst_port"].getInt() > 0: $soc["nat_dst_port"].getInt() else: ""
        
        let natSrcDisplay = if natSrcAddr != "n/a" and natSrcAddr != "": 
                            natSrcAddr & (if natSrcPort != "": ":" & natSrcPort else: "")
                          else: "n/a"
        let natDstDisplay = if natDstAddr != "n/a" and natDstAddr != "": 
                            natDstAddr & (if natDstPort != "": ":" & natDstPort else: "")
                          else: "n/a"
        let row = @[
          $pid, 
          soc["process_name"].getStr(), 
          soc["protocol"].getStr(), 
          soc["local_address"].getStr() & ":" & $soc["local_port"].getInt(), 
          soc["remote_address"].getStr() & ":" & $soc["remote_port"].getInt(),
          soc["state"].getStr(),
          sentSpeed,  # Changed from total bytes to speed
          receivedSpeed,  # Changed from total bytes to speed
          rtt,
          queueInfo,
          if soc.hasKey("retr"): $soc["retr"].getInt() else: "0",
          if soc["conntrack_state"].getStr() == "": "n/a" else: soc["conntrack_state"].getStr(),
          natSrcDisplay,
          natDstDisplay
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
      octolog.error(getCurrentExceptionMsg())
  )

  connectionTable.on("enter", proc(tb: tui_widget.Table, args: varargs[string]) = 
    try:
      if tb.rows().len() == 0:
        return

      let currRow = tb.selected()
      selectedProcess = parseInt(currRow.columns[0].text)
      selectedProcessName = currRow.columns[1].text
      selRecvChart.clearData()
      selSentChart.clearData()
      selRecvChart.title = fmt"⬇️ [{selectedProcessName}] bytes received (KB/s)"
      selSentChart.title = fmt"⬆️ [{selectedProcessName}] bytes sent (KB/s)"
      selRecvChart.show()
      selSentChart.show()
    except:
      selRecvChart.hide()
      selSentChart.hide()
      selRecvChart.clearData()
      selSentChart.clearData()
      selectedProcessName = ""
      selectedProcess = -1
  )

  let updateNetworkDataTask = toTask updateNetworkData(addr app, connectionTable.id)
  runInBackground(updateNetworkDataTask)

  # Add widgets to app
  app.addWidget(tcpConnCount, 0.25, 0.05)
  app.addWidget(udpConnCount, 0.25, 0.05)
  app.addWidget(conntrackCount, 0.25, 0.05)
  app.addWidget(natCount, 0.25, 0.05)
  app.addWidget(bsChart, 0.5, 0.25)
  app.addWidget(brChart, 0.5, 0.25)
  app.addWidget(connectionTable, 0.7, 0.6)
  app.addWidget(selSentChart, 0.3, 0.3)
  app.addWidget(selRecvChart, 0.3, 0.3, 0.7, 0.7, 0.0, 0.0)

  # Run the app
  app.run(nonBlocking=true)

  octologStop()

when isMainModule:
  main()