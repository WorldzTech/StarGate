/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "stargate",
	Short: "A CLI tool to use StarGate generator. Generate a random stream of bytes or process files and messages with stream cipher based on StarGate.",
	Long:  `StarGate is a deterministic pseudorandom byte generator (PRNG) designed for cryptographic applications, emphasizing high diffusion, nonlinearity, and computational efficiency. The algorithm is based on matrix transformations and uses a compact internal state (~547 bytes), making it ideal for lightweight systems such as Internet of Things (IoT) devices, real-time encryption, and key generation.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.stargate.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
