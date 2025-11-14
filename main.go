package main

import (
	"fmt"
	"os"
	"strconv"
	"waver/waver"
)

func main() {
	if len(os.Args) >= 4 {
		if os.Args[1] == "file" {
			key := ""
			if len(os.Args) == 5 {
				key = os.Args[4]
			}
			cipher, _ := waver.NewCipher(key)
			err := cipher.WorkWithFile(os.Args[2], os.Args[3])

			if err != nil {
				fmt.Println(err.Error())
			}
		}

		if os.Args[1] == "stream" {
			key := ""
			if len(os.Args) == 5 {
				key = os.Args[4]
			}

			n, _ := strconv.Atoi(os.Args[2])

			waver.CreateBin(n, os.Args[3], key)
			fmt.Println("Saved to", os.Args[3])
		}

	} else {
		fmt.Println("StarGate accepts 3 params: stargate [action] [bytes amount] [output file]")
	}
}
