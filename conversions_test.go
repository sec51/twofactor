package twofactor

import (
	"encoding/binary"
	"testing"
)

func TestRound(t *testing.T) {

	// TODO: test negative numbers, although not used in our case

	input := float64(3.7)
	expected := uint64(4)
	result := round(input)
	if result != expected {
		t.Fatalf("Expected %d - got %d\n", expected, result)
	}

	input = float64(3.5)
	expected = uint64(4)
	result = round(input)
	if result != expected {
		t.Fatalf("Expected %d - got %d\n", expected, result)
	}

	input = float64(3.499999999)
	expected = uint64(3)
	result = round(input)
	if result != expected {
		t.Fatalf("Expected %d - got %d\n", expected, result)
	}

	input = float64(3.0)
	expected = uint64(3)
	result = round(input)
	if result != expected {
		t.Fatalf("Expected %d - got %d\n", expected, result)
	}

	input = float64(3.9999)
	expected = uint64(4)
	result = round(input)
	if result != expected {
		t.Fatalf("Expected %d - got %d\n", expected, result)
	}
}

func TestBigEndianUint64(t *testing.T) {

	// convert ot bytes
	input := uint64(2984983220)
	inputBytes := bigEndianUint64(input)

	// convert from bytes back
	result := uint64FromBigEndian(inputBytes)
	if result != input {
		t.Fatal("Big endian conversion failed")
	}

	goResult := binary.BigEndian.Uint64(inputBytes[:])

	if goResult != input {
		t.Fatal("It's not a big endian representation")
	}

	input = uint64(18446744073709551615)
	inputBytes = bigEndianUint64(input)

	// convert from bytes back
	result = uint64FromBigEndian(inputBytes)
	if result != input {
		t.Fatal("Big endian conversion failed")
	}

	goResult = binary.BigEndian.Uint64(inputBytes[:])

	if goResult != input {
		t.Fatal("It's not a big endian representation")
	}

}

func TestBigEndianInt(t *testing.T) {

	// convert ot bytes
	input := int(2984983220)
	inputBytes := bigEndianInt(input)

	// convert from bytes back
	result := intFromBigEndian(inputBytes)
	if result != input {
		t.Fatal("Big endian conversion failed")
	}

	goResult := binary.BigEndian.Uint32(inputBytes[:])

	if int(goResult) != input {
		t.Fatal("It's not a big endian representation")
	}

}
