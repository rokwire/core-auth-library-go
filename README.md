# core-auth-library-go
Auth library for validation of Core Building Block auth tokens

## Installation
To install this package, use `go get`:

    go get github.com/rokwire/core-auth-library-go

This will then make the following packages available to you:

    github.com/rokwire/core-auth-library-go/authservice
    github.com/rokwire/core-auth-library-go/tokenauth
    github.com/rokwire/core-auth-library-go/sigauth

Import the `core-auth-library-go/authservice` package into your code using this template:

```go
package yours

import (
  ...

  "github.com/rokwire/core-auth-library-go/authservice"
)

func main() {
	// Instantiate an AuthService to maintain basic auth data
	authService := authservice.AuthService{
		ServiceID:   "sample",
		ServiceHost: "https://rokwire.illinois.edu/sample",
		FirstParty:  true,
		AuthBaseURL: "https://rokwire.illinois.edu/auth",
	}

	// Instantiate a remote ServiceRegLoader to load auth service registration record from auth service
	serviceRegLoader, err := authservice.NewRemoteServiceRegLoader(&authService, []string{"auth"})
	if err != nil {
		log.Fatalf("Error initializing remote service registration loader: %v", err)
	}

	// Instantiate a ServiceRegManager to manage the service registration data loaded by serviceRegLoader
	serviceRegManager, err := authservice.NewServiceRegManager(&authService, serviceRegLoader)
	if err != nil {
		log.Fatalf("Error initializing service registration manager: %v", err)
	}

	// Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
	staticTokenAuth := authservice.StaticTokenServiceAuth{ServiceToken: "sampleToken"}
	serviceAccountLoader, err := authservice.NewRemoteServiceAccountLoader(&authService, "sampleAccountID", staticTokenAuth)
	if err != nil {
		log.Fatalf("Error initializing remote service account loader: %v", err)
	}

	// Instantiate a remote ServiceAccountManager to manage service account-related data
	serviceAccountManager, err := authservice.NewServiceAccountManager(&authService, serviceAccountLoader)
	if err != nil {
		log.Fatalf("Error initializing service account manager: %v", err)
	}

    ...
}
```

## Upgrading
### Staying up to date
To update core-auth-library-go to the latest version, use `go get -u github.com/rokwire/core-auth-library-go`.

### Migration steps
Follow the steps below to upgrade to the associated version of this library. Note that the steps for each version are cumulative, so if you are attempting to upgrade by several versions, be sure to make the changes described for each version between your current version and the latest.

#### Unreleased
##### Breaking changes
The `AuthDataLoader` interface has been removed and the `AuthService` type has been refactored to contain basic configuration data needed to communicate with the ROKWIRE Auth Service.

The `ServiceRegManager` type has been added. To create a `ServiceRegManager`, a `ServiceRegLoader` must be created. The `ServiceRegLoader` is used to load service registration records retrieved from the ROKWIRE Auth Service, which are managed by the `ServiceRegManager`.

The `ServiceAccountManager` and `ServiceAccountLoader` types have been added. To create a `ServiceAccountManager`, a `ServiceAccountLoader` must be created. The`ServiceAccountLoader` is used to load access tokens from the ROKWIRE Auth Service, where the implementing service must hold an account. These access tokens are managed by the `ServiceAccountManager`.

See above for an example of how to create instances of these types to interact with a remote ROKWIRE Auth Service.

The `coreservice` package has been added. It declares the `CoreService` type, which is used to interface with services on the [Core Building Block](https://github.com/rokwire/core-building-block). All deleted account-related functionality previously used by the `AuthDataLoader` interface has been moved to the `coreservice` package.

The `KeyId` field in `sigauth.SignatureAuthHeader` is now called `KeyID`.

## ROKWIRE Auth Service
The ROKWIRE Auth Service is the system responsible for handling all user authentication and authorization in the ROKWIRE ecosystem. The Auth Service is a subsystem of the [Core Building Block](https://github.com/rokwire/core-building-block).

## Packages
This library contains several packages:

### `authservice`
The `authservice` package provides the `AuthService` type which contains the configurations to locate and communicate with the ROKWIRE Auth Service. The other packages in this library depend on the `AuthService` object, or other objects which depend on it, to handle any necessary communication with this central Auth Service.

This package also provides the `ServiceRegLoader`, `ServiceRegManager`, `ServiceAccountLoader`, and `ServiceAccountManager` types.

The `ServiceRegManager` type uses the configuration defined in an `AuthService` instance and a `ServiceRegLoader` instance to load, store, and manage service registration data (`ServiceReg` type).

The `ServiceAccountManager` type uses the configuration defined in an `AuthService` and a `ServiceAccountLoader` instance to load, storage, and manage service account data (e.g., access tokens, with the `AccessToken` type).

### `coreservice`
The `coreservice` package provides the `CoreService` type which contains the configurations and helper functions to utilize certain functions implemented by the ROKWIRE Core Building Block. One example of these functions is getting the IDs of accounts deleted within a set amount of time ago.

### `tokenauth`
The `tokenauth` package provides the `TokenAuth` type which exposes the interface to validate and authorize auth tokens generated by the ROKWIRE Auth Service.

### `sigauth`
The `sigauth` package provides the `SignatureAuth` type which exposes the interface to sign and verify HTTP requests to communicate securely between services within the ROKWIRE ecosystem.

### `authorization`
The `authorization` package provides a generic `Authorization` interface and a specific `CasbinAuthorization` and `CasbinScopeAuthorization` implementation of this interface that can be used with the `TokenAuth` object. There are two standard Casbin models that can be found in `authorization/authorization_model_string.conf` and `authorization/authorization_model_scope.conf` that can be used with each of these types respectively. You can also define your own model if neither of these fits the use case.

### `envloader`
The `envloader` package provides the `EnvLoader` interface which facilitates the loading of environment variables from various environments. Two standard implementations have been provided: `LocalEnvLoader` and `AWSSecretsManagerEnvLoader`. The `LocalEnvLoader` loads all variables from the environment variables set on the local machine, while the `AWSSecretsManagerEnvLoader` will load them from an AWS SecretsManager Secret.

#### `AWSSecretsManagerEnvLoader`
When using the `AWSSecretsManagerEnvLoader`, two environment variables must be set on the local machine to configure the specific secret to be accessed. The underlying infrastructure must also have the appropriate AWS permissions/roles to access the specied secret.

Environment Variables:
Name|Description
---|---
APP_SECRET_ARN | The AWS ARN of the AWS SecretsManager Secret to be accessed
AWS_REGION | The AWS region of the AWS SecretsManager Secret to be accessed

The `NewEnvLoader()` function can be used to automatically select and create the correct `EnvLoader` implementation object. If the two environment variables mentioned above are set, an `AWSSecretsManagerEnvLoader` will be returned, otherwise a `LocalEnvLoader` will be returned.

### `authutils`
The `authutils` package contains constants and standard utilities shared by the other packages.

## Usage
To get started, take a look at the `example/` directory.
