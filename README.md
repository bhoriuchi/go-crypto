# go-crypto
A simple package for encrypting and decrypting with a shared key

Each encrypted payload contains a version and all other data required to decrypt with a shared encryption key

## Example

```go
package main

import (
  "fmt"

  "github.com/bhoriuchi/go-crypto"
)

func main() {
  data := []byte("Snape Kills Dumbledore")
  
  key, _ := gocrypto.NewSecretKey(512)
  encryptedData, _ := gocrypto.Encrypt(key, data)
  decryptedData, _ := gocrypto.Decrypt(key, encryptedData)

  fmt.Printf("%t \n", string(data) == string(decryptedData))
  // true
}
```

Versions

* `Version 1` uses AES-256-GCM encryption