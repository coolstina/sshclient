![sshclient](assets/banner/sshclient.jpg)

Simple SSH client, the SSH connection is obtained through authentication.

## Installation

```shell script
go get -u github.com/coolstina/sshclient
```

## Example

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/coolstina/sshclient"
)

func main() {
	host := os.Getenv("DESTINATION_SSH_HOST")         // example: 10.10.0.0:22
	username := os.Getenv("DESTINATION_SSH_USERNAME") // example: hello_world
	password := os.Getenv("DESTINATION_SSH_PASSWORD") // example: hello_world
	client, err := sshclient.NewClient(host, username, password)
	if err != nil {
		log.Fatalf("failed to init ssh client: %+v", err)
	}

	fmt.Println(client.Instance().User())
    
    defer client.Instance().Close()
}
```