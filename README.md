# core-auth-library-go
Auth library for validation of Core Building Block auth tokens

## Installation
To install this package, use `go get`:

    go get github.com/rokwire/core-auth-library-go/v3

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
###### coreservice
* `coreservice.DeletedAccountsConfig` has been renamed to `coreservice.DeletedAccountsConfig` and the `Callback` field is now a function that takes `[]DeletedOrgAppMemberships` as its parameter instead of `[]string`.
* `coreservice.StartDeletedAccountsTimer` has been renamed to `coreservice.StartDeletedMembershipsTimer`.
* `DeletedOrgAppMemberships` represents a list of tenant account app memberships that have been deleted for the specified tenant (organization) and application. When a full account with multiple memberships is deleted, the ID of that account will appear in the list for multiple tenant-application pairs.

#### [3.0.1](https://github.com/rokwire/core-auth-library-go/compare/v3.0.0...v3.0.1)
##### Breaking changes
###### handlers
* All `tokenauth.Handler` types are now expected to be pointers.

###### authservice
* `NewServiceRegManager` now takes a `validate bool` argument that determines whether or not the service registration for the caller should be automatically validated. 

#### [3.0.0](https://github.com/rokwire/core-auth-library-go/compare/v2.2.0...v3.0.0)
##### Breaking changes
###### authservice
* `ServiceRegManager.ValidateServiceRegistrationKey` now takes a `*keys.PrivKey` as an argument instead of `*rsa.PrivateKey`.
* `PubKey` has been moved into the new `keys` package.

###### authutils
* `GetKeyFingerprint` has been removed and now exists as `SetKeyFingerprint` as a function on `keys.PubKey`.
* `GetPubKeyPem` has been removed and now exists as `Encode` as a function on `keys.PubKey`.

###### sigauth
* `SignatureAuth.CheckSignature` now takes a `*keys.PubKey` as an argument instead of `*rsa.PublicKey`.
* `SignatureAuth.CheckRequestSignature` now takes a `*keys.PubKey` as an argument instead of `*rsa.PublicKey`.
* `GetRequestDigest` now takes an `alg string` argument to specify which hash algorithm to use to compute the digest
* The `SignatureAuthHeader` algorithm check has been removed from `CheckRequest`, which has also been renamed to `ParseRequestSignature`. This better reflects that the function should be used to parse HTTP requests. The algorithm check has been moved to `CheckParsedRequestSignature`.

###### tokenauth
* `TokenAuth.ValidateCsrfTokenClaims` has been removed, as the tokenauth package is no longer used to handle CSRF tokens, and these tokens are now opaque.
* `TokenAuth.GetRequestTokens` has been renamed to `TokenAuth.GetAccessToken` and now only returns an access token found in the `Authorization` header of a request.
* `TokenAuth.CheckRequestTokens` has been renamed to `TokenAuth.CheckRequestToken` because now only the access token is checked.

#### [v2.0.1](https://github.com/rokwire/core-auth-library-go/compare/v1.0.9...v2.0.1)
##### Breaking changes

###### authservice
* The `AuthDataLoader` interface has been removed and the `AuthService` type has been refactored to contain basic configuration data needed to communicate with the ROKWIRE Auth Service.
* The `ServiceRegManager` type has been added. To create a `ServiceRegManager`, a `ServiceRegLoader` must be created. The `ServiceRegLoader` is used to load service registration records retrieved from the ROKWIRE Auth Service, which are managed by the `ServiceRegManager`.
* The `ServiceAccountManager` and `ServiceAccountLoader` types have been added. To create a `ServiceAccountManager`, a `ServiceAccountLoader` must be created. The `ServiceAccountLoader` is used to load access tokens from the ROKWIRE Auth Service, where the implementing service must hold an account. These access tokens are managed by the `ServiceAccountManager`.
* The `Kid` field in `PubKey` is now called `KeyID`.

See above for an example of how to create instances of these types to interact with a remote ROKWIRE Auth Service.

###### coreservice
* The `coreservice` package has been added. It declares the `CoreService` type, which is used to interface with services on the [Core Building Block](https://github.com/rokwire/core-building-block).
* All deleted account-related functionality previously used by the `AuthDataLoader` interface has been moved to the `coreservice` package.

###### sigauth
* The `KeyId` field in `SignatureAuthHeader` is now called `KeyID`, and it contains the SHA256 fingerprint of the signing service's public key instead of the signing service ID.
* Signed requests reflect this change, and checking signed requests requires the `KeyID` matches the public key fingerprint of a provided list of service registrations.

###### String Casbin Authorization Policy Model
A "description" (`descr`) parameter has been added to the Casbin string authorization policy model. This allows a description of each permission to be provided inline within the authorization policies. This change means that all Casbin string authorization policies (eg. permission policies) must be updated to include an additional column for this description. 

See [example/token/permissions_authorization_policy.csv](example/token/permissions_authorization_policy.csv) for an example of the new policy format.

**Note:** While this new column must exist, it will not impact the actual authorization policy and may be left empty if appropriate.

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

### `webauth`
The `webauth` package provides the utility functions that are useful when handling web applications. This includes setting cookies and verifying both cookies and headers to secure these web applications.

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

### `keys`
The `keys` package contains constants and generalized public key and private key wrapper types that are used by other packaages.

## Usage
To get started, take a look at the `example/` directory.
