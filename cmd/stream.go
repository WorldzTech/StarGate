/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
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
	Short: "Generates a byte stream",
	Long:  `Generates a bytes stream which you can save in file or print it in console.`,
	Run: func(cmd *cobra.Command, args []string) {
		consoleOutput, _ := cmd.Flags().GetBool("console")
		length, _ := cmd.Flags().GetInt("length")
		output, _ := cmd.Flags().GetString("output")
		key, _ := cmd.Flags().GetString("key")
		nounce, _ := cmd.Flags().GetString("nounce")

		if consoleOutput {
			cipher, _ := sg.NewCipher(key, nounce)
			for range length {
				fmt.Println(cipher.GetNextByte())
			}
		} else {
			sg.CreateBin(length, output, key)
			log.Printf("Byte stream is saved to %s.bin\n", output)
		}
	},
}

func init() {
	rootCmd.AddCommand(streamCmd)

	streamCmd.Flags().BoolP("console", "c", false, "Use this flag to print stream in console")
	streamCmd.Flags().IntP("length", "l", 256, "Use this flag to specify length of the stream. 256 by default.")
	streamCmd.Flags().StringP("output", "o", "stargate_stream", "Use this flag to provide file name as output file.")
	streamCmd.Flags().StringP("key", "k", "", "Specified key to use. If it is not specified will generate a random.")
	streamCmd.Flags().StringP("nonce", "n", "", "Specified nounce to use. If it is not specified will generate a random.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// streamCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// streamCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
