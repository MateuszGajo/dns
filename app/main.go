package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")

	if err != nil {
		log.Fatal(fmt.Printf("couldn't resolve addres, err: %v", err))
	}

	conn, err := net.ListenUDP("udp", addr)

	defer conn.Close()

	if err != nil {
		log.Fatal(fmt.Printf("couldn't create connection, err: %v", err))
	}

	buffer := make([]byte, 2048)

	for {
		size, source, err := conn.ReadFromUDP(buffer)

		if err != nil {
			log.Fatal(fmt.Printf("couldn't read msg err: %v", err))
			break
		}

		recivedData := buffer[:size]

		fmt.Printf("recived data: %s, source: %s \n", recivedData, source)

		response := []byte{}

		_, err = conn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}

}
