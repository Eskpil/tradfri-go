package main

import (
	"fmt"

	"github.com/eskpil/tradfri-go/tradfri"
)

func main() {
	client := tradfri.NewTradfriClient("your_gateway", "client_id", "psk")
	devices, err := client.ListDevices()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(devices)
}
