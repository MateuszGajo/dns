package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
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

func unmarshalHeader(data []byte) (Header, error) {
	if len(data) < 12 {
		return Header{}, fmt.Errorf("Invalid header size, need to be at least 12 bytes")
	}

	header := Header{}

	header.ID = binary.BigEndian.Uint16(data[0:2])

	header.QR = data[2] >> 7
	header.OPCODE = (data[2] >> 3) & 0xF
	header.AA = (data[2] >> 2) & 0x1
	header.TC = (data[2] >> 1) & 0x1
	header.RD = (data[2]) & 0x1

	header.RA = (data[3] >> 7)
	header.Z = (data[3] >> 4) & 0x7
	header.Z = data[3] & 0xF

	header.QDCOUNT = binary.BigEndian.Uint16(data[4:6])

	header.ANCOUNT = binary.BigEndian.Uint16(data[6:8])

	header.NSCOUNT = binary.BigEndian.Uint16(data[8:10])

	header.ARCOUNT = binary.BigEndian.Uint16(data[10:12])

	return header, nil
}

func (d Header) marshal() []byte {
	header := make([]byte, 12)

	// ID
	header[0] = byte(d.ID >> 8)
	header[1] = byte(d.ID & 0xFF)

	// Flags
	header[2] = d.QR << 7
	header[2] |= d.OPCODE << 3
	header[2] |= d.AA << 2
	header[2] |= d.TC << 1
	header[2] |= d.RD

	header[3] = d.RA << 7
	header[3] |= d.Z << 4
	header[3] |= d.RCODE

	header[4] = byte(d.QDCOUNT >> 8)
	header[5] = byte(d.QDCOUNT & 0xFF)

	header[6] = byte(d.ANCOUNT >> 8)
	header[7] = byte(d.ANCOUNT & 0xFF)

	header[8] = byte(d.NSCOUNT >> 8)
	header[9] = byte(d.NSCOUNT & 0xFF)

	header[10] = byte(d.ARCOUNT >> 8)
	header[11] = byte(d.ARCOUNT & 0xFF)

	return header
}

type Question struct {
	// Domain names in DNS packets are encoded as a sequence of labels.
	// Labels are encoded as <length><content>, where <length> is a single byte that specifies the length of the label, and <content> is the actual content of the label. The sequence of labels is terminated by a null byte (\x00).
	domainName string

	// 2 bytes
	// TYPE fields are used in resource records.  Note that these types are a
	// subset of QTYPEs.
	// TYPE            value and meaning
	// A               1 a host address
	// NS              2 an authoritative name server
	// MD              3 a mail destination (Obsolete - use MX)
	// MF              4 a mail forwarder (Obsolete - use MX)
	// CNAME           5 the canonical name for an alias
	// SOA             6 marks the start of a zone of authority
	// MB              7 a mailbox domain name (EXPERIMENTAL)
	// MG              8 a mail group member (EXPERIMENTAL)
	// MR              9 a mail rename domain name (EXPERIMENTAL)
	// NULL            10 a null RR (EXPERIMENTAL)
	// WKS             11 a well known service description
	// PTR             12 a domain name pointer
	// HINFO           13 host information
	// MINFO           14 mailbox or mail list information
	// MX              15 mail exchange
	// TXT             16 text strings
	questionType uint16

	// 2 bytes
	// CLASS fields appear in resource records.  The following CLASS mnemonics
	// and values are defined:
	// IN              1 the Internet
	// CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	// CH              3 the CHAOS class
	// HS              4 Hesiod [Dyer 87]
	questionClass uint16
}

func unmarshalQuestion(data []byte) (Question, int, error) {
	index := 0
	question := Question{}

	for len(data) > index && data[index] != 0 {
		if index != 0 {
			question.domainName += "."
		}
		length := int(data[index])

		label := data[index+1 : index+length+1]

		question.domainName += string(label)

		index += length + 1
	}
	index++
	question.questionType = binary.BigEndian.Uint16(data[index : index+2])
	question.questionClass = binary.BigEndian.Uint16(data[index+2 : index+4])

	return question, index + 4, nil
}

func (question *Question) marshal() []byte {
	var response []byte

	for _, label := range strings.Split(question.domainName, ".") {
		if len(label) == 0 {
			continue
		}
		response = append(response, byte(len(label)))
		response = append(response, label...)
	}

	response = append(response, 0)

	response = append(response, byte(question.questionType>>8))
	response = append(response, byte(question.questionType&0xFF))

	response = append(response, byte(question.questionClass>>8))
	response = append(response, byte(question.questionClass&0xFF))

	return response
}

type Answer struct {
	// Domain names in DNS packets are encoded as a sequence of labels.
	// Labels are encoded as <length><content>, where <length> is a single byte that specifies the length of the label, and <content> is the actual content of the label. The sequence of labels is terminated by a null byte (\x00).
	domainName string

	// 2 bytes
	// TYPE fields are used in resource records.  Note that these types are a
	// subset of QTYPEs.
	// TYPE            value and meaning
	// A               1 a host address
	// NS              2 an authoritative name server
	// MD              3 a mail destination (Obsolete - use MX)
	// MF              4 a mail forwarder (Obsolete - use MX)
	// CNAME           5 the canonical name for an alias
	// SOA             6 marks the start of a zone of authority
	// MB              7 a mailbox domain name (EXPERIMENTAL)
	// MG              8 a mail group member (EXPERIMENTAL)
	// MR              9 a mail rename domain name (EXPERIMENTAL)
	// NULL            10 a null RR (EXPERIMENTAL)
	// WKS             11 a well known service description
	// PTR             12 a domain name pointer
	// HINFO           13 host information
	// MINFO           14 mailbox or mail list information
	// MX              15 mail exchange
	// TXT             16 text strings
	answerType uint16

	// 2 bytes
	// CLASS fields appear in resource records.  The following CLASS mnemonics
	// and values are defined:
	// IN              1 the Internet
	// CS              2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	// CH              3 the CHAOS class
	// HS              4 Hesiod [Dyer 87]
	answerClass uint16

	// 4 byes
	// TTL (Time-To-Live)
	// The duration in seconds a record can be cached before requerying.
	TTL uint32

	// 2 byes
	// length RDLENGTH
	// Length of the RDATA field in bytes.
	RDLENGTH uint16

	// Variable
	// Data specific to the record type.
	data string
}

func (answer *Answer) marshal() []byte {
	var response []byte

	for _, label := range strings.Split(answer.domainName, ".") {
		if len(label) == 0 {
			continue
		}
		response = append(response, byte(len(label)))
		response = append(response, label...)
	}

	response = append(response, 0)

	response = append(response, byte(answer.answerType>>8))
	response = append(response, byte(answer.answerType&0xFF))

	response = append(response, byte(answer.answerClass>>8))
	response = append(response, byte(answer.answerClass&0xFF))

	response = append(response, byte(answer.TTL>>24))
	response = append(response, byte((answer.TTL>>16)&0xFF))
	response = append(response, byte((answer.TTL>>8)&0xFF))
	response = append(response, byte(answer.TTL&0xFF))

	response = append(response, byte(answer.RDLENGTH>>8))
	response = append(response, byte(answer.RDLENGTH&0xFF))

	for _, label := range strings.Split(answer.data, ".") {
		if len(label) == 0 {
			continue
		}
		n, err := strconv.Atoi(label)
		if err != nil {
			panic("cant convert")
		}
		response = append(response, byte(n))
	}

	return response
}

func unmarshalAnswer(data []byte) (Answer, int, error) {
	index := 0
	answer := Answer{}

	for len(data) > index && data[index] != 0 {
		if index != 0 {
			answer.domainName += "."
		}
		length := int(data[index])

		label := data[index+1 : index+length+1]

		answer.domainName += string(label)

		index += length + 1
	}
	index++
	answer.answerType = binary.BigEndian.Uint16(data[index : index+2])
	answer.answerClass = binary.BigEndian.Uint16(data[index+2 : index+4])

	answer.TTL = binary.BigEndian.Uint32(data[index+4 : index+8])
	answer.RDLENGTH = binary.BigEndian.Uint16(data[index+8 : index+10])

	for i := index + 10; i < index+10+int(answer.RDLENGTH); i++ {
		answer.data += strconv.Itoa(int(data[i]))
		if i < index+10+int(answer.RDLENGTH)-1 {

			answer.data += "."
		}
	}

	return answer, index + 10 + int(answer.RDLENGTH), nil
}

type DNSResponse struct {
	header   Header
	question []Question
	answer   []Answer
}

func (dnsResponse *DNSResponse) build() []byte {
	dnsResponse.header.QDCOUNT = uint16(len(dnsResponse.question))
	dnsResponse.header.ANCOUNT = uint16(len(dnsResponse.answer))
	resp := dnsResponse.header.marshal()

	for _, question := range dnsResponse.question {
		resp = append(resp, question.marshal()...)
	}

	for _, answer := range dnsResponse.answer {
		resp = append(resp, answer.marshal()...)
	}

	return resp
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
		fmt.Printf("raw data: %v \n", recivedData)
		recivedHeader, err := unmarshalHeader(recivedData)
		recivedQuestion, readBytes, err := unmarshalQuestion(recivedData[12:])
		recivedAnswer, readBytes, err := unmarshalAnswer(recivedData[12+readBytes:])
		fmt.Printf("%+v\n", recivedQuestion)
		fmt.Printf("%+v\n", recivedAnswer)
		if err != nil {
			log.Fatal(fmt.Printf("couldn't parse header err: %v", err))
			break
		}

		header := Header{
			ID:     recivedHeader.ID,
			QR:     1,
			RD:     recivedHeader.RD,
			OPCODE: recivedHeader.OPCODE,
		}
		if recivedHeader.OPCODE == 0 {
			header.RCODE = 0
		} else {
			header.RCODE = 4
		}
		question := Question{
			domainName:    recivedQuestion.domainName,
			questionClass: 1,
			questionType:  1,
		}
		answer := Answer{
			domainName:  recivedQuestion.domainName,
			answerType:  1,
			answerClass: 1,
			TTL:         60,
			RDLENGTH:    4,
			data:        "8.8.8.8",
		}
		response := DNSResponse{
			header:   header,
			question: []Question{question},
			answer:   []Answer{answer},
		}

		_, err = conn.WriteToUDP(response.build(), source)

		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}

}
