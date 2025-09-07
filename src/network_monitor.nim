import std/[os, strutils, sequtils, tables, strformat, times, json, parseutils]
import net, nativesockets
import octolog

type
  SocketInfo* = object
    protocol*: string
    localAddress*: string
    localPort*: int
    remoteAddress*: string
    remotePort*: int
    state*: string
    pid*: int
    processName*: string
    bytesSent*: int64
    bytesReceived*: int64
    txQueue*: int
    rxQueue*: int
    rtt*: int  # Round Trip Time in milliseconds
    rttVar*: int  # RTT variance
    uid*: int  # User ID
    timeout*: int  # Connection timeout
    retr*: int  # Retransmit count
    # New fields for connection tracking
    conntrackState*: string
    direction*: string  # original, reply, or unknown
    natSrcAddress*: string
    natSrcPort*: int
    natDstAddress*: string
    natDstPort*: int
    mark*: string
    zone*: string
    trafficBytes*: int64
    trafficPackets*: int64

  NetworkStats* = object
    totalBytesSent*: int64
    totalBytesReceived*: int64
    activeConnections*: int
    tcpConnections*: int
    udpConnections*: int
    connectionsByState*: Table[string, int]
    # New fields for enhanced stats
    conntrackEntries*: int
    blockedConnections*: int
    forwardedConnections*: int
    natTranslations*: int

proc hexToIpv4(hexStr: string): string =
  ## Convert hex string to IPv4 address
  if hexStr.len != 8:
    return "0.0.0.0"
  
  try:
    let a = parseHexInt(hexStr[6..7])
    let b = parseHexInt(hexStr[4..5])
    let c = parseHexInt(hexStr[2..3])
    let d = parseHexInt(hexStr[0..1])
    result = fmt"{a}.{b}.{c}.{d}"
  except:
    result = "0.0.0.0"

proc hexToIpv6(hexStr: string): string =
  ## Convert hex string to IPv6 address
  if hexStr.len != 32:
    return "::"
  
  try:
    var parts: seq[string] = @[]
    for i in countup(0, 31, 4):
      let part = hexStr[i..i+3]
      # Reverse byte order for each 4-byte group
      let reversedPart = part[2..3] & part[0..1]
      parts.add(reversedPart)
    
    # Join parts and compress zeros
    var ipv6 = parts.join(":")
    # Simple zero compression (replace longest sequence of :0000: with ::)
    ipv6 = ipv6.replace(":0000:", ":0:")
    ipv6 = ipv6.replace(":0:", "::")
    result = ipv6
  except:
    result = "::"

proc parseSocketState(hexState: string): string =
  ## Convert hex state to readable state name
  try:
    let state = parseHexInt(hexState)
    case state:
    of 0x01: "ESTABLISHED"
    of 0x02: "SYN_SENT"
    of 0x03: "SYN_RECV"
    of 0x04: "FIN_WAIT1"
    of 0x05: "FIN_WAIT2"
    of 0x06: "TIME_WAIT"
    of 0x07: "CLOSE"
    of 0x08: "CLOSE_WAIT"
    of 0x09: "LAST_ACK"
    of 0x0A: "LISTEN"
    of 0x0B: "CLOSING"
    else: fmt"UNKNOWN({hexState})"
  except:
    hexState

proc getNetworkInterfaceStats(): Table[string, tuple[rxBytes: int64, txBytes: int64]] =
  ## Get network interface statistics from /proc/net/dev
  result = initTable[string, tuple[rxBytes: int64, txBytes: int64]]()
  
  when defined(linux):
    if not fileExists("/proc/net/dev"):
      return
    
    let lines = readFile("/proc/net/dev").splitLines()
    if lines.len < 3:
      return
    
    # Skip first two header lines
    for i in 2..<lines.len:
      let line = lines[i].strip()
      if line.len == 0:
        continue
      
      let parts = line.split(':')
      if parts.len != 2:
        continue
      
      let interfaceName = parts[0].strip()
      let stats = parts[1].splitWhitespace()
      
      if stats.len >= 9:
        try:
          let rxBytes = parseBiggestInt(stats[0])
          let txBytes = parseBiggestInt(stats[8])
          result[interfaceName] = (rxBytes: rxBytes, txBytes: txBytes)
        except:
          continue

proc parseProcessNetDev(filePath: string): (int64, int64) =
  ## Parse process-specific network statistics from /proc/<pid>/net/dev
  result = (0, 0)  # (bytesReceived, bytesSent)
  
  if not fileExists(filePath):
    return
  
  try:
    let lines = readFile(filePath).splitLines()
    # Skip the first two header lines
    for i in 2..<lines.len:
      let line = lines[i].strip()
      if line.len == 0:
        continue
      
      let parts = line.split(':')
      if parts.len != 2:
        continue
      
      let stats = parts[1].splitWhitespace()
      if stats.len >= 16:  # Ensure we have all the fields
        try:
          let rxBytes = parseBiggestInt(stats[0])   # receive bytes
          let txBytes = parseBiggestInt(stats[8])   # transmit bytes
          result[0] += rxBytes
          result[1] += txBytes
        except:
          continue
  except:
    # If we can't read the file, just return zeros
    result = (0, 0)

proc parseConntrackValue(value: string): string =
  ## Parse conntrack values that may be quoted
  if value.len > 1 and value[0] == '"' and value[^1] == '"':
    return value[1..^2]
  return value

# proc parseConntrackLine(line: string): SocketInfo =
#   ## Parse a conntrack entry line into SocketInfo
#   result = SocketInfo()
#   result.conntrackState = "unknown"
#   result.direction = "unknown"
#   result.natSrcAddress = ""
#   result.natSrcPort = 0
#   result.natDstAddress = ""
#   result.natDstPort = 0
#   result.mark = ""
#   result.zone = ""
#   result.trafficBytes = 0
#   result.trafficPackets = 0

#   var parts = line.split({' ', '\t'})
#   var i = 0
#   while i < parts.len:
#     let part = parts[i].strip()
#     if part == "":
#       i += 1
#       continue
    
#     case part:
#     of "tcp", "udp", "icmp":
#       result.protocol = part
#     of "src":
#       if i+1 < parts.len:
#         result.localAddress = parseConntrackValue(parts[i+1])
#         i += 1
#     of "sport":
#       if i+1 < parts.len:
#         try:
#           result.localPort = parseInt(parseConntrackValue(parts[i+1]))
#         except:
#           discard
#         i += 1
#     of "dport":
#       if i+1 < parts.len:
#         try:
#           result.remotePort = parseInt(parseConntrackValue(parts[i+1]))
#         except:
#           discard
#         i += 1
#     of "state":
#       if i+1 < parts.len:
#         result.conntrackState = parseConntrackValue(parts[i+1])
#         i += 1
#     of " mark":
#       if i+1 < parts.len:
#         result.mark = parseConntrackValue(parts[i+1])
#         i += 1
#     of "[ASSURED]":
#       result.conntrackState = "ASSURED"
#     of "packets":
#       if i+1 < parts.len:
#         try:
#           result.trafficPackets = parseBiggestInt(parseConntrackValue(parts[i+1]))
#         except:
#           discard
#         i += 1
#     of "bytes":
#       if i+1 < parts.len:
#         try:
#           result.trafficBytes = parseBiggestInt(parseConntrackValue(parts[i+1]))
#         except:
#           discard
#         i += 1
#     of "[ src":
#       if i+3 < parts.len and parts[i+2] == "sport":
#         result.natSrcAddress = parseConntrackValue(parts[i+1])
#         try:
#           result.natSrcPort = parseInt(parseConntrackValue(parts[i+3]))
#         except:
#           discard
#         i += 3
#     of "dst":
#       if i+3 < parts.len and parts[i+2] == "dport":
#         result.natDstAddress = parseConntrackValue(parts[i+1])
#         try:
#           result.natDstPort = parseInt(parseConntrackValue(parts[i+3]))
#         except:
#           discard
#         i += 3
#       elif i+1 < parts.len:
#         result.remoteAddress = parseConntrackValue(parts[i+1])
#         i += 1
#     else:
#       discard
#     i += 1

# proc getConntrackEntries*(): seq[SocketInfo] =
#   ## Get connection tracking entries from /proc/net/nf_conntrack or /proc/net/ip_conntrack
#   result = @[]
  
#   when defined(linux):
#     # Try to read from /proc/net/nf_conntrack first
#     let conntrackPaths = ["/proc/net/nf_conntrack", "/proc/net/ip_conntrack"]
    
#     for path in conntrackPaths:
#       if fileExists(path):
#         try:
#           let lines = readFile(path).splitLines()
#           for line in lines:
#             if line.strip() != "":
#               let entry = parseConntrackLine(line)
#               if entry.protocol != "":
#                 result.add(entry)
#           break  # Successfully read from one of the paths
#         except:
#           continue

proc parseConntrackLine(line: string): SocketInfo =
  ## Parse a conntrack entry line into SocketInfo
  result = SocketInfo()
  result.conntrackState = "unknown"
  result.direction = "unknown"
  result.natSrcAddress = ""
  result.natSrcPort = 0
  result.natDstAddress = ""
  result.natDstPort = 0
  result.mark = ""
  result.zone = ""
  result.trafficBytes = 0
  result.trafficPackets = 0

  # Split by whitespace and process each field
  var parts = line.splitWhitespace()
  var i = 0
  var inReplyTuple = false
  
  while i < parts.len:
    let part = parts[i]
    
    case part:
    of "tcp", "udp", "icmp", "ipv4":
      if result.protocol == "":
        result.protocol = part
    of "src":
      if i+1 < parts.len:
        let address = parts[i+1]
        if not inReplyTuple:
          result.localAddress = address
        else:
          result.natDstAddress = address  # Reply src becomes NAT dst
        i += 1
    of "dst":
      if i+1 < parts.len:
        let address = parts[i+1]
        if not inReplyTuple:
          result.remoteAddress = address
        else:
          result.natSrcAddress = address  # Reply dst becomes NAT src
        i += 1
    of "sport":
      if i+1 < parts.len:
        try:
          let port = parseInt(parts[i+1])
          if not inReplyTuple:
            result.localPort = port
          else:
            result.natDstPort = port
        except:
          discard
        i += 1
    of "dport":
      if i+1 < parts.len:
        try:
          let port = parseInt(parts[i+1])
          if not inReplyTuple:
            result.remotePort = port
          else:
            result.natSrcPort = port
        except:
          discard
        i += 1
    of "[ASSURED]":
      result.conntrackState = "ASSURED"
    of "[UNREPLIED]":
      result.conntrackState = "UNREPLIED"
    of "mark":
      if i+1 < parts.len:
        result.mark = parts[i+1]
        i += 1
    else:
      # Check if we're entering the reply tuple
      if part.startsWith("src=") or (part == "src" and not inReplyTuple):
        inReplyTuple = true
      # Check for state information
      elif part.contains("ESTABLISHED") or part.contains("RELATED") or part.contains("NEW"):
        result.conntrackState = part
      # Check for packet/byte counters
      elif part.startsWith("packets="):
        try:
          result.trafficPackets = parseBiggestInt(part[8..^1])
        except:
          discard
      elif part.startsWith("bytes="):
        try:
          result.trafficBytes = parseBiggestInt(part[6..^1])
        except:
          discard
    
    i += 1

proc getConntrackEntries*(): seq[SocketInfo] =
  ## Get connection tracking entries from /proc/net/nf_conntrack or /proc/net/ip_conntrack
  result = @[]
  
  when defined(linux):
    let conntrackPaths = ["/proc/net/nf_conntrack", "/proc/net/ip_conntrack"]
    
    for path in conntrackPaths:
      if fileExists(path):
        try:
          # Try to read with different methods
          let content = readFile(path)
          # echo "Successfully read conntrack from: ", path
          
          let lines = content.splitLines()
          for lineNum, line in lines:
            let trimmedLine = line.strip()
            if trimmedLine.len > 0:
              let entry = parseConntrackLine(trimmedLine)
              if entry.protocol != "":
                result.add(entry)
          
          # echo "Found ", result.len, " conntrack entries"
          break
        except IOError as e:
          # echo "Permission denied reading ", path, ": ", e.msg
          # echo "Try running with sudo or check file permissions"
          continue
        except Exception as e:
          # echo "Error reading ", path, ": ", e.msg
          continue
    
    # If we couldn't read conntrack, return empty but don't fail
    # if result.len == 0:
      # echo "No conntrack entries available - this is normal for desktop systems"
      # continue


# Better correlation between socket and conntrack data
proc correlateSocketAndConntrack(sockets: var seq[SocketInfo], conntrackEntries: seq[SocketInfo]) =
  ## Correlate socket information with conntrack data
  for i, socket in sockets.mpairs:
    for entry in conntrackEntries:
      # Try to match by protocol, local/remote addresses and ports
      if socket.protocol.startsWith(entry.protocol) and
         socket.localAddress == entry.localAddress and
         socket.localPort == entry.localPort and
         socket.remoteAddress == entry.remoteAddress and
         socket.remotePort == entry.remotePort:
        
        # Copy conntrack-specific information
        socket.conntrackState = entry.conntrackState
        socket.direction = entry.direction
        socket.natSrcAddress = entry.natSrcAddress
        socket.natSrcPort = entry.natSrcPort
        socket.natDstAddress = entry.natDstAddress
        socket.natDstPort = entry.natDstPort
        socket.mark = entry.mark
        socket.zone = entry.zone
        socket.trafficBytes = entry.trafficBytes
        socket.trafficPackets = entry.trafficPackets
        break

proc getRTTFromNetlink(localAddr: string, localPort: int, remoteAddr: string, remotePort: int): int =
  ## Get RTT using netlink sockets - this requires more complex implementation
  ## For now, return 0 as RTT isn't easily accessible from /proc files
  result = 0
  
  # Real implementation would use:
  # 1. Create netlink socket
  # 2. Send TCP_DIAG request  
  # 3. Parse response for RTT info
  # This is quite complex and would require low-level socket programming

proc getTcpInfoFromSockstat(inode: string): tuple[rtt: int, rttVar: int] =
  ## Get TCP info from /proc/net/sockstat or other proc files
  result = (rtt: 0, rttVar: 0)
  
  # RTT information is not directly available in /proc/net/tcp
  # We would need to access the socket directly via syscalls
  # For now, we'll extract what we can from available data

proc parseTcpExtendedInfo(pid: int, fd: string): tuple[rtt: int, rttVar: int, cwnd: int] =
  ## Try to get extended TCP info from /proc/<pid>/net/sockstat
  result = (rtt: 0, rttVar: 0, cwnd: 0)
  
  when defined(linux):
    # TCP RTT info is not easily accessible from /proc files
    # The timer field in /proc/net/tcp contains timing info but not RTT directly
    # We'll need to work with what's available
    discard


# Try to get RTT from /proc/net/sockstat (limited info available)
proc getSystemSocketStats(): tuple[tcpInUse: int, tcpOrphan: int, tcpTw: int, tcpAlloc: int] =
  ## Get system-wide socket statistics
  result = (tcpInUse: 0, tcpOrphan: 0, tcpTw: 0, tcpAlloc: 0)
  
  when defined(linux):
    if fileExists("/proc/net/sockstat"):
      try:
        let content = readFile("/proc/net/sockstat")
        for line in content.splitLines():
          if line.startsWith("TCP:"):
            let parts = line.splitWhitespace()
            # Parse TCP statistics
            var i = 1
            while i < parts.len - 1:
              case parts[i]:
              of "inuse":
                result.tcpInUse = parseInt(parts[i+1])
              of "orphan":
                result.tcpOrphan = parseInt(parts[i+1])
              of "tw":
                result.tcpTw = parseInt(parts[i+1])
              of "alloc":
                result.tcpAlloc = parseInt(parts[i+1])
              i += 2
      except:
        discard

proc getSocketInfo(): seq[SocketInfo] =
  ## Get socket information from /proc/net/tcp and /proc/net/udp
  result = @[]
  
  when defined(linux):
    const procNetPath = "/proc/net/"
    let protocols = ["tcp", "tcp6", "udp", "udp6"]
    let interfaceStats = getNetworkInterfaceStats()
    
    for protocol in protocols:
      let filePath = procNetPath & protocol
      if not fileExists(filePath):
        continue
      
      let lines = readFile(filePath).splitLines()
      if lines.len < 2:
        continue
      
      # Debug: print header to understand format
      # if protocol == "tcp":
      #   echo "TCP header: ", lines[0]
      
      # Skip header line
      for i in 1..<lines.len:
        let line = lines[i].strip()
        if line.len == 0:
          continue
        
        let fields = line.splitWhitespace()
        if fields.len < 10:  # Minimum required fields
          # echo "Skipping line with insufficient fields: ", fields.len
          continue
        
        # Debug: print first line to understand format
        # if i == 1 and protocol == "tcp":
        #   echo "First TCP line fields:"
        #   for idx, field in fields:
        #     echo "  Field ", idx, ": '", field, "'"
        
        var socketInfo: SocketInfo
        socketInfo.protocol = protocol
        socketInfo.conntrackState = "none"
        socketInfo.direction = "unknown"
        socketInfo.natSrcAddress = ""
        socketInfo.natSrcPort = 0
        socketInfo.natDstAddress = ""
        socketInfo.natDstPort = 0
        socketInfo.mark = ""
        socketInfo.zone = ""
        socketInfo.trafficBytes = 0
        socketInfo.trafficPackets = 0
        
        # Parse local and remote addresses (fields 1 and 2)
        if fields.len > 2:
          let localAddrPort = fields[1].split(':')
          let remoteAddrPort = fields[2].split(':')
          
          if localAddrPort.len >= 2:
            let hexAddr = localAddrPort[0]
            if protocol.endsWith("6"):
              socketInfo.localAddress = hexToIpv6(hexAddr)
            else:
              socketInfo.localAddress = hexToIpv4(hexAddr)
            try:
              socketInfo.localPort = parseHexInt(localAddrPort[^1])
            except:
              socketInfo.localPort = 0
          
          if remoteAddrPort.len >= 2:
            let hexAddr = remoteAddrPort[0]
            if protocol.endsWith("6"):
              socketInfo.remoteAddress = hexToIpv6(hexAddr)
            else:
              socketInfo.remoteAddress = hexToIpv4(hexAddr)
            try:
              socketInfo.remotePort = parseHexInt(remoteAddrPort[^1])
            except:
              socketInfo.remotePort = 0
        
        # Parse state (field 3)
        if fields.len > 3:
          socketInfo.state = parseSocketState(fields[3])
        
        # Parse queue sizes (field 4: tx_queue:rx_queue)
        if fields.len > 4:
          let queueField = fields[4]
          let queueParts = queueField.split(':')
          if queueParts.len >= 2:
            try:
              let txHex = queueParts[0]
              let rxHex = queueParts[1] 
              socketInfo.txQueue = parseHexInt(txHex)
              socketInfo.rxQueue = parseHexInt(rxHex)
              
              # Debug queue parsing
              # if i <= 3:  # Debug first few entries
              #   echo "Queue field: '", queueField, "' -> TX: ", socketInfo.txQueue, ", RX: ", socketInfo.rxQueue
            except ValueError as e:
              # echo "Error parsing queue field '", queueField, "': ", e.msg
              socketInfo.txQueue = 0
              socketInfo.rxQueue = 0
        
        # Parse timer info (field 5: tr:tm->when)
        if fields.len > 5:
          let timerField = fields[5]
          let timerParts = timerField.split(':')
          if timerParts.len >= 2:
            try:
              # This doesn't give us RTT directly, but timer info
              let tr = parseHexInt(timerParts[0])
              let tmWhen = parseHexInt(timerParts[1])
              
              # We can't get RTT from this, set to 0 for now
              socketInfo.rtt = 0
              socketInfo.rttVar = 0
              
              # Debug timer parsing
              # if i <= 3:
              #   echo "Timer field: '", timerField, "' -> tr: ", tr, ", tm->when: ", tmWhen
            except:
              socketInfo.rtt = 0
              socketInfo.rttVar = 0
        
        # Parse retransmit count (field 6)
        if fields.len > 6:
          try:
            socketInfo.retr = parseHexInt(fields[6])
          except:
            socketInfo.retr = 0
        
        # Parse UID (field 7)
        if fields.len > 7:
          try:
            socketInfo.uid = parseHexInt(fields[7])
          except:
            socketInfo.uid = 0
        
        # Parse timeout (field 8)
        if fields.len > 8:
          try:
            socketInfo.timeout = parseHexInt(fields[8])
          except:
            socketInfo.timeout = 0
        
        # Parse inode (field 9)
        var inode = ""
        if fields.len > 9:
          inode = fields[9]
        
        # Get PID and process info from inode
        if inode != "0" and inode != "":
          # Look up PID by inode in /proc/
          for pidDir in walkDir("/proc/"):
            if pidDir.kind == pcDir and pidDir.path.splitPath().tail.all(isDigit):
              let pidNum = pidDir.path.splitPath().tail
              let fdPath = pidDir.path / "fd"
              if dirExists(fdPath):
                for fdFile in walkDir(fdPath):
                  if fdFile.kind == pcLinkToFile or fdFile.kind == pcLinkToDir:
                    try:
                      let linkTarget = expandSymlink(fdFile.path)
                      if linkTarget.contains("socket:[" & inode & "]"):
                        socketInfo.pid = parseInt(pidNum)
                        
                        # Get process name
                        let cmdlinePath = pidDir.path / "cmdline"
                        if fileExists(cmdlinePath):
                          let cmdline = readFile(cmdlinePath)
                          if cmdline.len > 0:
                            let cmdParts = cmdline.split('\0')
                            if cmdParts.len > 0:
                              socketInfo.processName = cmdParts[0].extractFilename()
                        
                        # Try to get RTT from TCP socket info file (if exists)
                        if protocol.startsWith("tcp"):
                          let tcpInfoPath = pidDir.path / "net" / "tcp"
                          # Note: /proc/<pid>/net/tcp doesn't contain RTT either
                          # RTT would need to be obtained via netlink sockets or other methods
                          
                        # Get process-specific network statistics  
                        let netStatPath = pidDir.path / "net/dev"
                        if fileExists(netStatPath):
                          let (rxBytes, txBytes) = parseProcessNetDev(netStatPath)
                          socketInfo.bytesReceived = rxBytes
                          socketInfo.bytesSent = txBytes
                        
                        break
                    except OSError:
                      continue
        
        result.add(socketInfo)


proc getNetworkStatistics*(): NetworkStats =
  ## Get overall network statistics
  result = NetworkStats()
  let socketInfo = getSocketInfo()
  let conntrackEntries = getConntrackEntries()
  
  # Get interface statistics for total bytes
  let interfaceStats = getNetworkInterfaceStats()
  for iface, stats in interfaceStats:
    result.totalBytesSent += stats.txBytes
    result.totalBytesReceived += stats.rxBytes

  for conn in socketInfo:
    result.activeConnections += 1

    if conn.protocol.startsWith("tcp"):
      result.tcpConnections += 1
    elif conn.protocol.startsWith("udp"):
      result.udpConnections += 1

    if not result.connectionsByState.hasKey(conn.state):
      result.connectionsByState[conn.state] = 0
    result.connectionsByState[conn.state] += 1

  # Process conntrack statistics
  result.conntrackEntries = conntrackEntries.len
  result.natTranslations = 0
  result.blockedConnections = 0
  result.forwardedConnections = 0
  
  for entry in conntrackEntries:
    if entry.natSrcAddress != "" or entry.natDstAddress != "":
      result.natTranslations += 1
    
    if entry.conntrackState == "DROP" or entry.conntrackState == "DENIED":
      result.blockedConnections += 1
    
    # Assume forwarded connections are those with NAT
    if entry.natSrcAddress != "" or entry.natDstAddress != "":
      result.forwardedConnections += 1

# proc getActiveConnections*(): seq[SocketInfo] =
#   ## Get list of active network connections
#   var sockets = getSocketInfo()
#   let conntrackEntries = getConntrackEntries()
  
#   # Merge conntrack info with socket info where possible
#   # This is a simplified merge - in practice you'd match by IPs/ports
#   result = sockets
#   for entry in conntrackEntries:
#     result.add(entry)

proc getActiveConnections*(): seq[SocketInfo] =
  ## Get list of active network connections
  var sockets = getSocketInfo()
  let conntrackEntries = getConntrackEntries()
  
  # Correlate the data instead of just appending
  # If no conntrack entries due to permissions, just return socket info
  if conntrackEntries.len == 0:
    # Set default values for conntrack fields
    for i, socket in sockets.mpairs:
      socket.conntrackState = "n/a"
      socket.direction = "n/a"
      socket.natSrcAddress = ""
      socket.natSrcPort = 0
      socket.natDstAddress = ""
      socket.natDstPort = 0
      socket.mark = ""
      socket.zone = ""
      socket.trafficBytes = 0
      socket.trafficPackets = 0
  else:
    # Correlate the data
    correlateSocketAndConntrack(sockets, conntrackEntries)
  
  result = sockets

proc formatBytes*(bytes: int64): string =
  ## Format bytes to human readable format
  const units = ["B", "KB", "MB", "GB", "TB"]
  var value = bytes.float
  var unitIndex = 0

  while value >= 1024 and unitIndex < units.high:
    value /= 1024
    unitIndex += 1

  result = fmt"{value:.1f} {units[unitIndex]}"

proc getUpdate*(): string = 
  ## Get socket info, network stats and return in json format
  ## {
  ##   "socket_info": []
  ## }
  let socketInfo = getActiveConnections()
  let networkStats = getNetworkStatistics()
  
  # Create connections by state table for JSON serialization
  var connectionsByState = initTable[string, int]()
  for state, count in networkStats.connectionsByState:
    connectionsByState[state] = count
  
  var jsonObj = %*{
    "timestamp": now().toTime().toUnix(),
    "network_stats": {
      "total_bytes_sent": networkStats.totalBytesSent,
      "total_bytes_received": networkStats.totalBytesReceived,
      "active_connections": networkStats.activeConnections,
      "tcp_connections": networkStats.tcpConnections,
      "udp_connections": networkStats.udpConnections,
      "connections_by_state": connectionsByState,
      "conntrack_entries": networkStats.conntrackEntries,
      "blocked_connections": networkStats.blockedConnections,
      "forwarded_connections": networkStats.forwardedConnections,
      "nat_translations": networkStats.natTranslations
    },
    "socket_info": []
  }
  
  for socket in socketInfo:
    let socketJson = %*{
      "protocol": socket.protocol,
      "local_address": socket.localAddress,
      "local_port": socket.localPort,
      "remote_address": socket.remoteAddress,
      "remote_port": socket.remotePort,
      "state": socket.state,
      "pid": socket.pid,
      "process_name": socket.processName,
      "bytes_sent": socket.bytesSent,
      "bytes_received": socket.bytesReceived,
      "tx_queue": socket.txQueue,
      "rx_queue": socket.rxQueue,
      "rtt": socket.rtt,
      "rtt_var": socket.rttVar,
      "uid": socket.uid,
      "timeout": socket.timeout,
      "retr": socket.retr,
      "conntrack_state": socket.conntrackState,
      "direction": socket.direction,
      "nat_src_address": socket.natSrcAddress,
      "nat_src_port": socket.natSrcPort,
      "nat_dst_address": socket.natDstAddress,
      "nat_dst_port": socket.natDstPort,
      "mark": socket.mark,
      "zone": socket.zone,
      "traffic_bytes": socket.trafficBytes,
      "traffic_packets": socket.trafficPackets
    }
    jsonObj["socket_info"].add(socketJson)
  
  result = $jsonObj


proc debugConntrackAvailability*() =
  ## Debug procedure to check conntrack availability
  echo "=== Conntrack Debug Info ==="
  
  let paths = [
    "/proc/net/nf_conntrack",
    "/proc/net/ip_conntrack", 
    "/proc/sys/net/netfilter/nf_conntrack_max",
    "/proc/sys/net/nf_conntrack_max"
  ]
  
  for path in paths:
    if fileExists(path):
      echo path, ": EXISTS"
      try:
        let content = readFile(path)
        echo "  Size: ", content.len, " bytes"
        if path.contains("conntrack") and not path.contains("max"):
          let lines = content.splitLines()
          echo "  Lines: ", lines.len
          if lines.len > 0:
            echo "  First line: ", lines[0][0..min(100, lines[0].len-1)]
      except:
        echo "  ERROR: Cannot read"
    else:
      echo path, ": NOT FOUND"
  
  # Check if conntrack kernel modules are loaded
  if fileExists("/proc/modules"):
    let modules = readFile("/proc/modules")
    let conntrackModules = ["nf_conntrack", "nf_conntrack_ipv4", "nf_nat"]
    for module in conntrackModules:
      if module in modules:
        echo "Module ", module, ": LOADED"
      else:
        echo "Module ", module, ": NOT LOADED"
  
  echo "=========================="

# debugConntrackAvailability()