package main

import (
	"reflect"
	"testing"
)

func TestHeader(t *testing.T) {
	header := Header{
		ID: 1234,
		QR: 1,
	}

	bytes := header.marshal()

	if !reflect.DeepEqual(bytes, []byte{byte(4), byte(210), byte(128), 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("Invalid header, expected: %v, got: %v", []byte{byte(4), byte(210), byte(128), 0, 0, 0, 0, 0, 0, 0, 0, 0}, bytes)
	}

}

func TestQuestion(t *testing.T) {
	question := Question{
		domainName:    "codecrafters.io",
		questionClass: 1,
		questionType:  1,
	}

	bytes := question.marshal()

	if !reflect.DeepEqual(bytes, []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01")) {
		t.Errorf("Invalid header, expected: %v, got: %v", []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"), bytes)
	}

}

func TestAnswer(t *testing.T) {
	answer := Answer{
		domainName:  "codecrafters.io",
		answerType:  1,
		answerClass: 1,
		TTL:         60,
		RDLENGTH:    4,
		data:        "8.8.8.8",
	}

	bytes := answer.marshal()
	expectedAnswerBytes := []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08")

	if !reflect.DeepEqual(bytes, expectedAnswerBytes) {
		t.Errorf("Invalid header, expected: %v, got: %v", expectedAnswerBytes, bytes)
	}

}

func TestUnmarshalQuestion(t *testing.T) {
	data := []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01")

	question, bytesRead, err := unmarshalQuestion(data)

	if err != nil {
		t.Error(err)
	}

	if bytesRead != 21 {
		t.Errorf("expected to read 21 bytes, read: %v", bytesRead)
	}

	if question.domainName != "codecrafters.io" {
		t.Errorf("Expected domain to be codecrafters.io, got: %v", question.domainName)
	}

	if question.questionClass != 1 {
		t.Errorf("Expected questionClass to be 1 got : %v", question.questionClass)
	}

	if question.questionType != 1 {
		t.Errorf("Expected questionType to be 1 got : %v", question.questionType)
	}
}

func TestUnmarshalAnswer(t *testing.T) {
	data := []byte("\x0ccodecrafters\x02io\x00\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04\x08\x08\x08\x08")

	answer, bytesRead, err := unmarshalAnswer(data)

	if err != nil {
		t.Error(err)
	}

	if bytesRead != 31 {
		t.Errorf("expected to read 31 bytes, read: %v", bytesRead)
	}

	if answer.domainName != "codecrafters.io" {
		t.Errorf("Expected domain to be codecrafters.io, got: %v", answer.domainName)
	}

	if answer.answerClass != 1 {
		t.Errorf("Expected answerClass to be 1 got : %v", answer.answerClass)
	}

	if answer.answerType != 1 {
		t.Errorf("Expected answerType to be 1 got : %v", answer.answerType)
	}

	if answer.TTL != 60 {
		t.Errorf("Expected answer ttl to be 60 got : %v", answer.TTL)
	}

	if answer.RDLENGTH != 4 {
		t.Errorf("Expected rdlength to be 4 got : %v", answer.RDLENGTH)
	}

	if answer.data != "8.8.8.8" {
		t.Errorf("Expected data to be 8.8.8.8: %v", answer.data)
	}

}
