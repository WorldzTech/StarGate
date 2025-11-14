package waver

import (
	"fmt"
	"os"
	"github.com/schollz/progressbar/v3"
)

func CreateBin(n int, filename, key string) {
	// создаём генератор
	w, err := NewWaver(key)
	if err != nil {
		panic(err)
	}

	// создаём/открываем файл
	file, err := os.Create(filename + ".bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// сколько байт хотим записать

	bar := progressbar.Default(int64(n))

	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = w.GetNext()
		bar.Add(1)
	}

	// записываем буфер в файл
	if _, err := file.Write(buf); err != nil {
		panic(err)
	}

	fmt.Println("Файл записан.")
}