package cryptoengine

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {

	// create key base folder
	if err := createBaseKeyFolder(testKeyPath); err != nil {
		t.Error(err)
	}

	if !fileExists(testKeyPath) {
		t.Fatalf("%s should have been created", testKeyPath)
	}
}

func TestFileUtils(t *testing.T) {

	// create key base folder
	if err := createBaseKeyFolder(testKeyPath); err != nil {
		t.Error(err)
	}

	filename := "temp.txt"
	dataString := "TEST DATA"
	data := []byte(dataString)

	// write a simple file
	err := writeFile(filename, data)
	if err != nil {
		t.Error(err)
	}

	// rewrite the same file, it should trigger an error
	err = writeFile(filename, data)
	if err != os.ErrExist {
		t.Errorf("The expected error is: os.ErrExist, instead we've got: %s\n", err)
	}

	// check if the file exists, it should
	if !fileExists(filename) {
		t.Fatal("The file should exist!")
	}

	// read the file back
	storedData, err := readFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	// read the data back
	storedString := string(storedData)
	if storedString != dataString {
		t.Error("The data in the file is corrupted")
	}

	// delete the file
	if err := deleteFile(filename); err != nil {
		t.Fatal(err)
	}

	// delete the keys folder
	if err := removeFolder(testKeyPath); err != nil {
		t.Fatal(err)
	}

}

func TestKeyFileUtils(t *testing.T) {

	// create key base folder
	if err := createBaseKeyFolder(testKeyPath); err != nil {
		t.Error(err)
	}

	var key [keySize]byte
	var err error
	filename := "test_secret.key"
	key, err = generateSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := writeKey(filename, testKeysFolderPrefixFormat, key[:]); err != nil {
		t.Fatal(err)
	}

	storedKey, err := readKey(filename, testKeysFolderPrefixFormat)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key[:], storedKey[:]) != 0 {
		t.Fatal("The generated random key and the stored one, do not match")
	}

	if err := deleteFile(fmt.Sprintf(testKeysFolderPrefixFormat, filename)); err != nil {
		t.Error(err)
	}

	// delete the keys folder
	if err := removeFolder(testKeyPath); err != nil {
		t.Fatal(err)
	}

}
