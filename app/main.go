package main

import (
	"fmt"
	"log"
	"net"
)

type Header struct {
	// 16 bits
	// Packet Identifier (ID)
	// A random ID assigned to query packets. Response packets must reply with the same ID.
	ID uint16

	// 1 bit
	// Query/Response Indicator (QR)
	// 1 for a reply packet, 0 for a question packet.

	QR uint8

	// 4 bits
	// Operation Code (OPCODE)
	// Specifies the kind of query in a message.  //
	// 0 - a standard query (QUERY)
	// 1 - an inverse query (IQUERY)
	// 2 - a server status request (STATUS)
	// 3-15 reserved for future use
	OPCODE uint8

	// 1 bit
	// Authoritative Answer (AA)
	// 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	AA uint8

	// 1 bit
	// Truncation (TC)
	// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	TC uint8

	// 1 bit
	// Recursion Desired (RD)
	// Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
	RD uint8

	// 1 bit
	// Recursion Available (RA)
	// Server sets this to 1 to indicate that recursion is available.
	RA uint8

	// 3 bits
	// Reserved (Z)
	// Used by DNSSEC queries. At inception, it was reserved for future use. Must be zero in all queries and responses.
	Z uint8

	// 4 bits
	// Response Code (RCODE)
	// Response code indicating the status of the response.
	RCODE uint8

	// 16 bits
	// Question Count (QDCOUNT)
	// Number of questions in the Question section.
	QDCOUNT uint16

	// 16 bits
	// Answer Record Count (ANCOUNT)
	// Number of records in the Answer section.
	ANCOUNT uint16

	// 16 bits
	// Authority Record Count (NSCOUNT)
	// Number of records in the Authority section.
	NSCOUNT uint16

	// 16 bits
	// Additional Record Count (ARCOUNT)
	// Number of records in the Additional section.
	ARCOUNT uint16
}

func (dh Header) marshal() []byte {
	header := make([]byte, 12)

	// ID
	header[0] = byte(dh.ID >> 8)
	header[1] = byte(dh.ID & 0xFF)

	// Flags

	header[2] = dh.QR << 7
	header[2] |= dh.OPCODE << 3
	header[2] |= dh.AA << 2
	header[2] |= dh.TC << 1
	header[2] |= dh.RD

	header[3] = dh.RA << 7
	header[3] |= dh.Z << 4
	header[3] |= dh.RCODE

	header[4] = byte(dh.QDCOUNT >> 8)
	header[5] = byte(dh.QDCOUNT & 0xFF)

	header[6] = byte(dh.ANCOUNT >> 8)
	header[7] = byte(dh.ANCOUNT & 0xFF)

	header[8] = byte(dh.NSCOUNT >> 8)
	header[9] = byte(dh.NSCOUNT & 0xFF)

	header[10] = byte(dh.ARCOUNT >> 8)
	header[11] = byte(dh.ARCOUNT & 0xFF)

	return header

}

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

		header := Header{
			ID: 1234,
			QR: 1,
		}
		response := header.marshal()

		_, err = conn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}

}
