import std/[os, strutils, sequtils, tables, strformat, times, json]
import net, nativesockets

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

  NetworkStats* = object
    totalBytesSent*: int64
    totalBytesReceived*: int64
    activeConnections*: int
    tcpConnections*: int
    udpConnections*: int
    connectionsByState*: Table[string, int]


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
      
      # Skip header line
      for i in 1..<lines.len:
        let line = lines[i].strip()
        if line.len == 0:
          continue
        
        let fields = line.splitWhitespace()
        if fields.len < 10:
          continue
        
        var socketInfo: SocketInfo
        socketInfo.protocol = protocol
        
        # Parse local and remote addresses
        let localAddrPort = fields[1].split(':')
        let remoteAddrPort = fields[2].split(':')
        
        if localAddrPort.len >= 2:
          let hexAddr = localAddrPort[0]
          if protocol.endsWith("6"):
            socketInfo.localAddress = hexToIpv6(hexAddr)
          else:
            socketInfo.localAddress = hexToIpv4(hexAddr)
          socketInfo.localPort = parseHexInt(localAddrPort[^1])
        
        if remoteAddrPort.len >= 2:
          let hexAddr = remoteAddrPort[0]
          if protocol.endsWith("6"):
            socketInfo.remoteAddress = hexToIpv6(hexAddr)
          else:
            socketInfo.remoteAddress = hexToIpv4(hexAddr)
          socketInfo.remotePort = parseHexInt(remoteAddrPort[^1])
        
        # Parse state (convert hex to readable state)
        socketInfo.state = parseSocketState(fields[3])
        
        # Get bytes sent/received from /proc/net/dev for network interfaces
        # Note: Per-socket byte counts aren't directly available in /proc/net/tcp
        # We'll get process-specific network stats if available
        if fields.len > 13:
          try:
            # Some kernels provide tx_queue and rx_queue in fields 4 and 5
            socketInfo.bytesSent = parseHexInt(fields[4])
            socketInfo.bytesReceived = parseHexInt(fields[5])
          except:
            socketInfo.bytesSent = 0
            socketInfo.bytesReceived = 0
        
        # Get PID from inode mapping
        let inode = fields[9]
        if inode != "0":
          # Look up PID by inode in /proc/
          for pidDir in walkDir("/proc/"):
            if pidDir.kind == pcDir and pidDir.path.splitPath().tail.all(isDigit):
              let fdPath = pidDir.path / "fd"
              if dirExists(fdPath):
                for fdFile in walkDir(fdPath):
                  if fdFile.kind == pcLinkToFile or fdFile.kind == pcLinkToDir:
                    try:
                      let linkTarget = expandSymlink(fdFile.path)
                      if linkTarget.contains("socket:[" & inode & "]"):
                        socketInfo.pid = parseInt(pidDir.path.splitPath().tail)
                        
                        # Get process name
                        let cmdlinePath = pidDir.path / "cmdline"
                        if fileExists(cmdlinePath):
                          let cmdline = readFile(cmdlinePath)
                          if cmdline.len > 0:
                            socketInfo.processName = cmdline.split('\0')[0].extractFilename()
                        
                        # Get process-specific network statistics
                        let netStatPath = pidDir.path / "net/dev"
                        if fileExists(netStatPath):
                          let (rxBytes, txBytes) = parseProcessNetDev(netStatPath)
                          socketInfo.bytesReceived = rxBytes
                          socketInfo.bytesSent = txBytes
                        
                        break
                    except OSError:
                      # Some symlinks might not be readable
                      continue
        
        result.add(socketInfo)

proc getNetworkStatistics*(): NetworkStats =
  ## Get overall network statistics
  result = NetworkStats()
  let socketInfo = getSocketInfo()
  
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

proc getActiveConnections*(): seq[SocketInfo] =
  ## Get list of active network connections
  getSocketInfo()

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
  # get socket info, network stats and return in json format
  # {
  #   "socket_info": []
  # }
  let socketInfo = getSocketInfo()
  let networkStats = getNetworkStatistics()
  
  var jsonObj = %*{
    "timestamp": now().toTime().toUnix(),
    "network_stats": {
      "total_bytes_sent": networkStats.totalBytesSent,
      "total_bytes_received": networkStats.totalBytesReceived,
      "active_connections": networkStats.activeConnections,
      "tcp_connections": networkStats.tcpConnections,
      "udp_connections": networkStats.udpConnections,
      "connections_by_state": networkStats.connectionsByState
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
      "bytes_received": socket.bytesReceived
    }
    jsonObj["socket_info"].add(socketJson)
  
  result = $jsonObj

# echo getUpdate()