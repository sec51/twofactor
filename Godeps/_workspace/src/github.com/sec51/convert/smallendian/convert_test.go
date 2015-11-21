package smallendian

import (
	"encoding/binary"
	"testing"
)

func TestSmallEndianUint64(t *testing.T) {

	// convert ot bytes
	input := uint64(2984983220)
	inputBytes := ToUint64(input)

	// convert from bytes back
	result := FromUint64(inputBytes)
	if result != input {
		t.Errorf("Small endian conversion failed. Got %d instead of %d\n", result, input)
	}

	goResult := binary.LittleEndian.Uint64(inputBytes[:])

	if goResult != input {
		t.Fatal("It's not a small endian representation")
	}

	input = uint64(18446744073709551615)
	inputBytes = ToUint64(input)

	// convert from bytes back
	result = FromUint64(inputBytes)
	if result != input {
		t.Fatal("Small endian conversion failed")
	}

	goResult = binary.LittleEndian.Uint64(inputBytes[:])

	if goResult != input {
		t.Fatal("It's not a small endian representation")
	}

}

func TestSmallEndianInt(t *testing.T) {

	// convert ot bytes
	input := int(2984983220)
	inputBytes := ToInt(input)

	// convert from bytes back
	result := FromInt(inputBytes)
	if result != input {
		t.Fatal("Small endian conversion failed")
	}

	goResult := binary.LittleEndian.Uint32(inputBytes[:])

	if int(goResult) != input {
		t.Fatal("It's not a small endian representation")
	}

}
