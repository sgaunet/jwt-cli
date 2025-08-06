package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// genkeysCmd represents the genkeys command.
var genkeysCmd = &cobra.Command{
	Use:   "genkeys",
	Short: "print commands example to generate keys for ES256, ES384, ES512, RS256, RS384, RS512",
	Long:  `print commands example to generate keys for ES256, ES384, ES512, RS256, RS384, RS512`,
}

var genkeysES256Cmd = &cobra.Command{
	Use:   "es256",
	Short: "print commands example to generate keys for ES256",
	Long:  `print commands example to generate keys for ES256`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("openssl ecparam -genkey -name prime256v1  -noout -out ecdsa-p256-private.pem")
		fmt.Println("openssl ec -in ecdsa-p256-private.pem -pubout -out ecdsa-p256-public.pem")
	},
}

var genkeysES384Cmd = &cobra.Command{
	Use:   "es384",
	Short: "print commands example to generate keys for ES384",
	Long:  `print commands example to generate keys for ES384`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("openssl ecparam -name secp384r1 -genkey -noout -out jwtES384key.pem")
		fmt.Println("openssl ec -in jwtES384key.pem -pubout -out jwtES384pubkey.pem")
	},
}

var genkeysES512Cmd = &cobra.Command{
	Use:   "es512",
	Short: "print commands example to generate keys for ES512",
	Long:  `print commands example to generate keys for ES512`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("openssl ecparam -genkey -name secp521r1 -noout -out ecdsa-p521-private.pem")
		fmt.Println("openssl ec -in ecdsa-p521-private.pem -pubout -out ecdsa-p521-public.pem")
	},
}

var genkeysRS256Cmd = &cobra.Command{
	Use:   "rs256",
	Short: "print commands example to generate keys for RS256",
	Long:  `print commands example to generate keys for RS256`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P '' -f RS256.key")
		fmt.Println("openssl rsa -in RS256.key -pubout -outform PEM -out RS256.key.pub")
	},
}

var genkeysRS384Cmd = &cobra.Command{
	Use:   "rs384",
	Short: "print commands example to generate keys for RS384",
	Long:  `print commands example to generate keys for RS384`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("ssh-keygen -t rsa -b 4096 -E SHA384 -m PEM -P '' -f RS384.key")
		fmt.Println("openssl rsa -in RS384.key -pubout -outform PEM -out RS384.key.pub")
	},
}

var genkeysRS512Cmd = &cobra.Command{
	Use:   "rs512",
	Short: "print commands example to generate keys for RS512",
	Long:  `print commands example to generate keys for RS512`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P '' -f RS512.key")
		fmt.Println("openssl rsa -in RS512.key -pubout -outform PEM -out RS512.key.pub")
	},
}