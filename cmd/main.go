package main

import (
	"flag"
	"vem_message_generator/pkg/service"
	"vem_message_generator/pkg/utils"
)

var (
	ecdhPublicKey    = flag.String("ecdhPublicKey", "", "ecdh public key")
	ecdhPrivateKey   = flag.String("ecdhPrivateKey", "", "ecdh private key")
	encryptedMessage = flag.String("encryptedMessage", "", "encrypted message")
	validatorsList   = flag.String("validators", "", "comma-separated list of validators")
	pk               = flag.String("pk", "", "private key")
)

func main() {
	flag.Parse()
	srv := service.NewGenerator()
	if utils.ValidateString(pk) {
		srv.GenerateVEMRequest(*pk, *validatorsList)
	} else {
		srv.DecryptData(ecdhPublicKey, ecdhPrivateKey, encryptedMessage)
	}
}
