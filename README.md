# kmtr/totp

# Example

## HMacSha1, 30 seconds, 6 digit, Base32 encoded secret

```go
package main

import (
	"encoding/base32"
	"fmt"
	"log"
	"os"
)

func main() {
	generator := NewGenerator("sha1", 30, 6, nil)
	err := generator.SetSecretString(base32.StdEncoding, "JBSWY3DPEHPK3PXP")
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
	// Generate a 2FA code
	code, err := generator.Generate()
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(2)
	}
	fmt.Println(code)

	// Generate a 2FA URL
	urlOf2fa := generator.URL(base32.StdEncoding, "label", "issuer")
	fmt.Println(urlOf2fa)
}
```