/*
Copyright © 2025 Daniel Baikalov <felix.trof@gmail.com>
*/
package cmd

import (
	"fmt"
	"log"
	"stargate/sg"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// messageCmd represents the message command
var messageCmd = &cobra.Command{
	Use:   "message",
	Short: "Encrypts or decrypts a text message using StarGate stream cipher",
	Long: `Encrypts or decrypts a short text message using StarGate stream cipher.

- Default: encryption.
- Use --decrypt (-d) to decrypt.
- Key: 512-byte string (512 chars). Random if omitted.
- Nonce: 16-byte string (16 chars). Random if omitted.
- Output format: [nonce(16)] + [ciphertext] (as text or bytes).

Input can be:
  - Plain text: "hello"
  - Hex bytes: "48 65 6c 6c 6f" (with --byteinput)

Output modes:
  - Text: default
  - Bytes: --bytemode (-b)
    - Hex: --bytemode
    - Decimal: --bytemode --numericbytes (-u)`,
	Example: `stargate message "attack at dawn"
  stargate message "attack at dawn" -b
  stargate message "10 20 30..." --byteinput -b
  stargate message "d1a2b3...ciphertext" -d -k <key-hex>`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Println("Need a single messages provided")
			return
		}

		key, _ := cmd.Flags().GetString("key")
		nonce, _ := cmd.Flags().GetString("nonce")
		bytemode, _ := cmd.Flags().GetBool("bytemode")
		numericBytes, _ := cmd.Flags().GetBool("numericbytes")
		decryptMode, _ := cmd.Flags().GetBool("decrypt")
		byteInput, _ := cmd.Flags().GetBool("byteinput")

		cipher, err := sg.NewCipher(key, nonce)

		if err != nil {
			log.Fatalf("Failed to initialize cipher: %v", err)
		}

		cipherText := ""

		if byteInput {
			parts := strings.Fields(args[0])
			bytes := make([]byte, len(parts))

			for i, part := range parts {
				val, err := strconv.ParseUint(part, 16, 8)
				if err != nil {
					log.Fatal(err)
				}
				bytes[i] = byte(val)
			}

			args[0] = string(bytes)
		}

		if decryptMode {
			nonceB := []byte(args[0])[:16]
			nonce := string(nonceB)

			cipher.ReinitializeWithNewNonce(nonce)
			args[0] = args[0][16:]
		}

		for _, char := range args[0] {
			cipherText += string(char ^ rune(cipher.GetNextByte()))
		}

		if !decryptMode {
			nonceStr := ""
			for _, char := range cipher.Nonce {
				nonceStr += string(char)
			}
			cipherText = nonceStr + cipherText
		}

		if bytemode {
			bytes := []byte(cipherText)
			var parts []string

			if numericBytes {
				for _, b := range bytes {
					parts = append(parts, fmt.Sprintf("%d", b))
				}
			} else {
				for _, b := range bytes {
					parts = append(parts, fmt.Sprintf("%02x", b))
				}
			}

			result := strings.Join(parts, " ")
			fmt.Println(result)
		} else {
			fmt.Println(cipherText)
		}
	},
}

func init() {
	rootCmd.AddCommand(messageCmd)

	messageCmd.Flags().StringP("key", "k", "",
		"512-byte key as string (512 chars). If empty — random key is generated.")

	messageCmd.Flags().StringP("nonce", "n", "",
		"16-byte nonce as string (16 chars). If empty — random nonce is generated.")

	messageCmd.Flags().BoolP("bytemode", "b", false,
		"Output as space-separated bytes.")

	messageCmd.Flags().BoolP("numericbytes", "u", false,
		"With --bytemode: output bytes as decimal (0-255), not hex.")

	messageCmd.Flags().BoolP("decrypt", "d", false,
		"Decrypt mode. Input must contain nonce prefix (16 bytes).")

	messageCmd.Flags().Bool("byteinput", false,
		"Input is space-separated hex bytes (e.g. '48 65 6c 6c 6f').")
}
