package sg

import (
	"fmt"
	"os"

	"github.com/schollz/progressbar/v3"
)

func CreateBin(n int, filename, key string) {
	w, err := NewWaver(key, "", false)
	if err != nil {
		panic(err)
	}

	file, err := os.Create(filename + ".bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	bar := progressbar.Default(int64(n))

	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = w.GetNext()
		bar.Add(1)
	}

	if _, err := file.Write(buf); err != nil {
		panic(err)
	}

	fmt.Println("Done")
}
