package event

import "fmt"

func PrintStringHandler(b []byte) {
	fmt.Println(string(b))
}

func NullHandler(b []byte) {}
