package cryptoengine

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

const (
	keyPath     = "keys"
	testKeyPath = "test_keys"
)

var (
	osSeparator, _             = strconv.Unquote(strconv.QuoteRuneToASCII(os.PathSeparator))
	keysFolderPrefixFormat     = fmt.Sprintf("%s%s", keyPath, osSeparator) + "%s"
	testKeysFolderPrefixFormat = fmt.Sprintf("%s%s", testKeyPath, osSeparator) + "%s"
)

// create the keys folder if it does not exist, with the proper permission
func init() {
	if err := createBaseKeyFolder(keyPath); err != nil {
		log.Println(err)
	}
}

// Check if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Check if a key file exists
func keyFileExists(filename string) bool {
	_, err := os.Stat(fmt.Sprintf(keysFolderPrefixFormat, filename))
	return err == nil
}

// Read the full file into a byte slice
func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Writes a file with read only permissions
// If the file already exists then it returns the specific error: os.ErrExist
// This is thanks to the flag O_CREATE
func writeFile(filename string, data []byte) error {

	if fileExists(filename) {
		return os.ErrExist
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0400)
	if err != nil {
		log.Println(err)
		return err
	}

	_, err = file.Write(data)
	return err

}

// Read the key file into a 32 byte array
func readKey(filename, pathFormat string) ([keySize]byte, error) {
	var data32 [keySize]byte

	// read the data back
	data, err := readFile(fmt.Sprintf(pathFormat, filename))
	if err != nil {
		return data32, err
	}
	// decode from base64
	dst := make([]byte, len(data))
	_, err = base64.StdEncoding.Decode(dst, data)
	if err != nil {
		return data32, err
	}
	// fill in the 32 byte array witht he data and return it
	copy(data32[:], dst[:keySize])
	return data32, err
}

// Write the key file base64 encoded
func writeKey(filename, pathFormat string, data []byte) error {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	filePath := fmt.Sprintf(pathFormat, filename)
	return writeFile(filePath, dst)
}

// Check if the file or directory exists and then deletes it
func deleteFile(filename string) error {
	if fileExists(filename) {
		return os.Remove(filename)
	}
	return nil
}

func createBaseKeyFolder(path string) error {
	if fileExists(path) {
		return nil
	}
	return os.MkdirAll(path, 0700)
}

func removeFolder(path string) error {
	return os.RemoveAll(path)
}
