/*
Copyright © 2025 Daniel Baikalov <felix.trof@gmail.com>
*/
package cmd

import (
	"log"
	"stargate/sg"

	"github.com/spf13/cobra"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file <input-file>",
	Short: "Encrypts or decrypts a file using StarGate stream cipher",
	Long: `Encrypts or decrypts a file using StarGate stream cipher.

- Default: encryption.
- Use --decrypt to decrypt.
- Key: 512-byte string (512 chars). Random if omitted.
- Nonce: 16-byte string (16 chars). Random if omitted.
- Output: [nonce(16)] + [ciphertext]

Examples:
  stargate file input.txt -o out.sg
  stargate file out.sg -o input.txt -d -k <512-byte-string>
`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			log.Fatal("A single file path is required")
		}

		inputPath := args[0]
		outputPath, _ := cmd.Flags().GetString("output")
		keyStr, _ := cmd.Flags().GetString("key")
		nonceStr, _ := cmd.Flags().GetString("nonce")
		decryptMode, _ := cmd.Flags().GetBool("decrypt")

		cipher, err := sg.NewCipher(keyStr, nonceStr, false)
		if err != nil {
			log.Fatalf("Failed to initialize cipher: %v", err)
		}

		if decryptMode {
			if err := cipher.DecryptFile(inputPath, outputPath); err != nil {
				log.Fatalf("Processing failed: %v", err)
			}
		} else {
			if err := cipher.EncryptFile(inputPath, outputPath); err != nil {
				log.Fatalf("Processing failed: %v", err)
			}
		}

		log.Printf("File processed successfully → %s", outputPath)
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)

	fileCmd.Flags().StringP("output", "o", "stargate_output", "Output file path.")
	fileCmd.Flags().StringP("key", "k", "", "512-byte key as string (512 chars). If empty — random key is generated.")
	fileCmd.Flags().StringP("nonce", "n", "", "16-byte nonce as string (16 chars). If empty — random nonce is generated.")
	fileCmd.Flags().BoolP("decrypt", "d", false, "Decrypt mode (default: encrypt).")

	_ = fileCmd.MarkFlagFilename("output")
}
