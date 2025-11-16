/*
Copyright © 2025 Daniel Baikalov <felix.trof@gmail.com>
*/
package cmd

import (
	"fmt"
	"log"
	"stargate/sg"

	"github.com/spf13/cobra"
)

// streamCmd represents the stream command
var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Generates a pseudorandom byte stream using StarGate",
	Long: `Generates a deterministic pseudorandom byte stream using StarGate PRNG.

- Key: 512-byte string (512 chars). Random if omitted.
- Nonce: 16-byte string (16 chars). Random if omitted.
- Output: raw bytes (no nonce prepended).
- Use --console to print bytes to stdout.
- Otherwise: saves to binary file.`,
	Example: `stargate stream -l 512 -o stream.bin
  	stargate stream -c -l 8 -b`,
	Run: func(cmd *cobra.Command, args []string) {
		consoleOutput, _ := cmd.Flags().GetBool("console")
		length, _ := cmd.Flags().GetInt("length")
		output, _ := cmd.Flags().GetString("output")
		key, _ := cmd.Flags().GetString("key")
		nonce, _ := cmd.Flags().GetString("nonce")
		hexOutput, _ := cmd.Flags().GetBool("hexoutput")

		if consoleOutput {
			cipher, err := sg.NewCipher(key, nonce)

			if err != nil {
				log.Fatalf("Failed to initialize cipher: %v", err)
			}

			for range length {
				if hexOutput {
					fmt.Println(fmt.Sprintf("%02x", cipher.GetNextByte()))
				} else {
					fmt.Println(cipher.GetNextByte())
				}
			}
		} else {
			sg.CreateBin(length, output, key)
			log.Printf("Byte stream is saved to %s.bin\n", output)
		}
	},
}

func init() {
	rootCmd.AddCommand(streamCmd)

	streamCmd.Flags().BoolP("console", "c", false,
		"Print stream to console in hexdump format.")

	streamCmd.Flags().IntP("length", "l", 256,
		"Length of stream in bytes. Default: 256.")

	streamCmd.Flags().StringP("output", "o", "stargate_stream",
		"Base name for output file. Saved as <name>.bin.")

	streamCmd.Flags().StringP("key", "k", "",
		"512-byte key as string (512 chars). If empty — random key is generated.")

	streamCmd.Flags().StringP("nonce", "n", "",
		"16-byte nonce as string (16 chars). If empty — random nonce is generated.")

	streamCmd.Flags().BoolP("hexoutput", "b", false,
		"Output as hex bytes.")

}
