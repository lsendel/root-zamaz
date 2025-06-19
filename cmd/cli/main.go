package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"mvp.local/pkg/client"
	"mvp.local/pkg/handlers"
)

var (
	apiURL   string
	username string
	password string
	email    string
	token    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mvpctl",
		Short: "Developer CLI for Zero Trust Auth MVP",
	}
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080/api", "API base URL")

	// login command
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login and obtain a token",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(apiURL)
			resp, err := c.Login(context.Background(), username, password)
			if err != nil {
				return err
			}
			fmt.Printf("Token: %s\nRefresh: %s\n", resp.Token, resp.RefreshToken)
			return nil
		},
	}
	loginCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	loginCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	loginCmd.MarkFlagRequired("username")
	loginCmd.MarkFlagRequired("password")

	// register command
	registerCmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(apiURL)
			req := handlers.RegisterRequest{Username: username, Email: email, Password: password}
			resp, err := c.Register(context.Background(), req)
			if err != nil {
				return err
			}
			fmt.Printf("User %s created\n", resp.ID)
			return nil
		},
	}
	registerCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	registerCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
	registerCmd.Flags().StringVarP(&email, "email", "e", "", "Email")
	registerCmd.MarkFlagRequired("username")
	registerCmd.MarkFlagRequired("password")
	registerCmd.MarkFlagRequired("email")

	// whoami command
	whoamiCmd := &cobra.Command{
		Use:   "whoami",
		Short: "Get current user info",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(apiURL)
			resp, err := c.Me(context.Background(), token)
			if err != nil {
				return err
			}
			fmt.Printf("User: %s (%s)\n", resp.Username, resp.Email)
			return nil
		},
	}
	whoamiCmd.Flags().StringVarP(&token, "token", "t", "", "Access token")
	whoamiCmd.MarkFlagRequired("token")

	rootCmd.AddCommand(loginCmd, registerCmd, whoamiCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
