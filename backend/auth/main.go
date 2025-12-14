package main

import (
	"log"

	"github.com/tiptenbrink/tiauth-faroe/tiauth"
)

func main() {
	cfg, err := tiauth.ParseFlagsAndConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := tiauth.Run(cfg); err != nil {
		log.Fatal(err)
	}
}
