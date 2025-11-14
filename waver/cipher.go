package waver

import (
	"github.com/schollz/progressbar/v3"
	"os"
)

type Cipher struct {
	waver *Waver
}

func NewCipher(key string) (*Cipher, error) {
	waver, err := NewWaver(key)

	if err != nil {
		return nil, err
	}

	return &Cipher{
		waver: waver,
	}, nil
}

func (c *Cipher) WorkWithFile(filepath, newFilePath string) error {
	b, err := os.ReadFile(filepath)

	if err != nil {
		return err
	}

	workedBytes := make([]byte, len(b))

	bar := progressbar.Default(int64(len(b)))

	for i := 0; i < len(b); i++ {
		workedBytes[i] = b[i] ^ c.waver.GetNext()
		bar.Add(1)
	}

	file, _ := os.Create(newFilePath)
	_, err = file.Write(workedBytes)
	if err != nil {
		return err
	}

	file.Close()

	return nil
}