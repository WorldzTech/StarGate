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

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Use to process file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			log.Println("To process file provide it name")
			return
		}

		key, _ := cmd.Flags().GetString("key")
		output, _ := cmd.Flags().GetString("output")

		cipher, _ := sg.NewCipher(key)
		err := cipher.WorkWithFile(args[0], output)

		if err != nil {
			fmt.Println(err.Error())
		}

		log.Printf("File processed and saved as %s\n", output)
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)

	fileCmd.Flags().StringP("output", "o", "stargate_output", "Output file where result of prcessing will be saved")
	fileCmd.Flags().StringP("key", "k", "", "Specified key to use. If it is not specified will generate a random.")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// fileCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// fileCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
