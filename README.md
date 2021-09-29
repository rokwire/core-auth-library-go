# core-auth-library
Auth library for validation of Core Building Block auth tokens

## Installation
To install this package, use `go get`:

    go get github.com/rokwire/core-auth-library

This will then make the following packages available to you:

    github.com/rokwire/core-auth-library/authservice
    github.com/rokwire/core-auth-library/tokenauth
    github.com/rokwire/core-auth-library/sigauth

Import the `core-auth-library/authservice` package into your code using this template:

```go
package yours

import (
  ...

  "github.com/rokwire/core-auth-library/authservice"
)

func main() {
    serviceLoader := authservice.NewRemoteServiceRegLoader("https://auth.rokmetro.com", nil)
	authService, err := authservice.NewAuthService("example", "https://sample.rokmetro.com", serviceLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

    ...
}
```

### Staying up to date
To update core-auth-library to the latest version, use `go get -u github.com/rokwire/core-auth-library`.