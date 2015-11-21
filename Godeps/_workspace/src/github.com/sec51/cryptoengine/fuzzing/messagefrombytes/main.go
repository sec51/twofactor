// this file is used for fuzz testing only
package main

import (
	"fmt"
	_ "github.com/sec51/cryptoengine"
)

func main() {
	fmt.Println("This function is for fuzzing only.")
}

// func Fuzz(data []byte) int {
// 	_, err := cryptoengine.MessageFromBytes(data)
// 	if err == nil { // means it was parsed successfully
// 		return 1
// 	}

// 	fmt.Printf("Error parsing message: %s with data %s\n", err, data)
// 	return 0
// }
