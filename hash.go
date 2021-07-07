package main

import (
	"bufio"
	"fmt"
	"hash/fnv"
"strings"
	"os"
)

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func main() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter String: ")
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\n", "", -1)

	hash := hash(text)
         
	hex := fmt.Sprint(hash)

	fmt.Println("Hashed: " + hex)
}
	