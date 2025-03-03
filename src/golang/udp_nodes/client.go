package udp_nodes

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)



var useEbpf = false

func StartClient() {
	// Define the server address (change "localhost" and port if needed)
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.2:7072")
	if err != nil {
		fmt.Printf("Error resolving address: %v\n", err)
		os.Exit(1)
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Printf("Error dialing UDP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("Connected to UDP server at %s\n", serverAddr.String())
	for {
		// 創建消息，預留 SeqInfo 的空間
		msg := fmt.Sprintf("Hi %d from client!!", rand.Int())
		// 確保消息長度是固定的，並且留出足夠空間給 SeqInfo
		msgWithPadding := make([]byte, len(msg)+16)  // 16 = sizeof(SeqInfo)
		copy(msgWithPadding, []byte(msg))

		// Send the message to the server
		_, err := conn.Write(msgWithPadding)
		if err != nil {
			fmt.Printf("Error sending data: %v\n", err)
			continue
		}
		time.Sleep(time.Second)
	}
}
