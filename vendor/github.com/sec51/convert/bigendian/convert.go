package bigendian

// helper function which converts a uint64 to a []byte in Big Endian
func ToUint64(n uint64) [8]byte {
	data := [8]byte{}
	data[0] = byte((n >> 56) & 0xFF)
	data[1] = byte((n >> 48) & 0xFF)
	data[2] = byte((n >> 40) & 0xFF)
	data[3] = byte((n >> 32) & 0xFF)
	data[4] = byte((n >> 24) & 0xFF)
	data[5] = byte((n >> 16) & 0xFF)
	data[6] = byte((n >> 8) & 0xFF)
	data[7] = byte(n & 0xFF)
	return data
}

// helper function which converts a big endian []byte to a uint64
func FromUint64(data [8]byte) uint64 {
	i := (uint64(data[7]) << 0) | (uint64(data[6]) << 8) |
		(uint64(data[5]) << 16) | (uint64(data[4]) << 24) |
		(uint64(data[3]) << 32) | (uint64(data[2]) << 40) |
		(uint64(data[1]) << 48) | (uint64(data[0]) << 56)
	return uint64(i)
}

// helper function which converts a int to a []byte in Big Endian
func ToInt(n int) [4]byte {
	data := [4]byte{}
	data[0] = byte((n >> 24) & 0xFF)
	data[1] = byte((n >> 16) & 0xFF)
	data[2] = byte((n >> 8) & 0xFF)
	data[3] = byte(n & 0xFF)
	return data
}

// helper function which converts a big endian []byte to a int
func FromInt(data [4]byte) int {
	i := (int(data[3]) << 0) | (int(data[2]) << 8) |
		(int(data[1]) << 16) | (int(data[0]) << 24)
	return int(i)
}
