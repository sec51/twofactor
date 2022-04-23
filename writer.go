package twofactor

import (
	"bufio"
	"bytes"

	"github.com/yeqown/go-qrcode/writer/standard"
)

// BytesWriter is a writer that writes QR Code to in memory bytes.
type QRCodeBytesWriter struct {
	*bufio.Writer
}

func (writer QRCodeBytesWriter) Close() error {
	return writer.Flush()
}

func NewQRCodeBytesWriter(buffer *bytes.Buffer, opts ...standard.ImageOption) *standard.Writer {
	return standard.NewWithWriter(QRCodeBytesWriter{bufio.NewWriter(buffer)}, opts...)
}
