/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"stargate/sg"
	"strings"

	"github.com/spf13/cobra"
)

// messageCmd represents the message command
var messageCmd = &cobra.Command{
	Use:   "message",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Println("Need a single messages provided")
			return
		}

		key, _ := cmd.Flags().GetString("key")
		bytemode, _ := cmd.Flags().GetBool("bytemode")
		numericBytes, _ := cmd.Flags().GetBool("numericbytes")

		cipher, _ := sg.NewCipher(key)

		cipherText := ""

		for _, char := range args[0] {
			cipherText += string(char ^ rune(cipher.GetNextByte()))
		}

		if bytemode {
			bytes := []byte(cipherText)
			var parts []string

			if numericBytes {
				for _, b := range bytes {
					parts = append(parts, fmt.Sprintf("%02x", b))
				}
			} else {
				for _, b := range bytes {
					parts = append(parts, fmt.Sprintf("%d", b))
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

	messageCmd.Flags().StringP("key", "k", "", "Specified key to use. If it is not specified will generate a random.")
	messageCmd.Flags().BoolP("bytemode", "b", false, "Display byte view of cipher text")
	messageCmd.Flags().BoolP("numericbytes", "n", false, "Display byte view as numeric bytes")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// messageCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// messageCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
