package udp_nodes

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)



func StartServer(serverId int, port int) {
	addr, err := resolveUDPAddr("127.0.0.1", port)
	if err != nil {
		panic(err)
	}

	conn, err := createUDPListener(addr)
	if err != nil {
		panic(err)
	}
	listenAndServe(serverId, conn)
}

func listenAndServe(serverId int, conn *net.UDPConn) {
    defer conn.Close()
    buffer := make([]byte, 1024)

    log.Printf("UDP server %d listening on %s\n", serverId, conn.LocalAddr().String())

    for {
        n, addr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Error reading from UDP: %v\n", err)
            continue
        }

        seqInfoSize := binary.Size(SeqInfo{})
        seqInfoBytes := buffer[n-seqInfoSize : n]
        var seqInfo SeqInfo
        
        binary.Read(bytes.NewReader(seqInfoBytes), binary.LittleEndian, &seqInfo)
        
        message := string(buffer[:n-seqInfoSize])
        currentTime := time.Now().UnixNano()
        latency := currentTime - int64(seqInfo.Timestamp)
        
        log.Printf("Server %d Received from %s:\n"+
            "\tSequence: %d\n"+
            "\tTimestamp: %d (current: %d)\n"+
            "\tLatency: %dns\n"+
            "\tMessage: %s\n", 
            serverId, 
            addr,
            seqInfo.Sequence,
            seqInfo.Timestamp,
            currentTime,
            latency,
            message)
    }
}

func createUDPListener(udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("error listening on UDP address %v: %v", udpAddr, err)
	}
	return conn, nil
}

func resolveUDPAddr(ip string, port int) (*net.UDPAddr, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("error resolving UDP address %s: %v", addr, err)
	}
	return udpAddr, nil
}
