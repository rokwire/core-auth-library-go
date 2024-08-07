# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
## [3.2.1] - 2024-08-02
### Fixed
- Upgrade dependencies

## [3.2.0] - 2024-02-29
### Changed
- Expose invalid claims [#94](https://github.com/rokwire/core-auth-library-go/issues/94)

## [3.1.0] - 2023-08-30
### Added
- Add username field to token claims [#91](https://github.com/rokwire/core-auth-library-go/issues/91)

## [3.0.1] - 2023-03-16
### Fixed
- Mismatching token signing algorithms do not trigger service reg refresh [#88](https://github.com/rokwire/core-auth-library-go/issues/88)

## [3.0.0] - 2023-03-09
### Added
- BREAKING: Encapsulate key management [#76](https://github.com/rokwire/core-auth-library-go/issues/76)
- BREAKING: Add webauth package for web apps [#83](https://github.com/rokwire/core-auth-library-go/issues/83)
- Claims can access resource function [#85](https://github.com/rokwire/core-auth-library-go/issues/85)

## [2.2.0] - 2022-11-23
### Added
- Function param on base token auth handlers [#79](https://github.com/rokwire/core-auth-library-go/issues/79)
### Fixed
- Empty request body on refresh service token in makeRequest [#77](https://github.com/rokwire/core-auth-library-go/issues/77)

## [2.1.0] - 2022-11-16
### Added
- Define TokenAuthHandlers [#73](https://github.com/rokwire/core-auth-library-go/issues/73)

## [2.0.3] - 2022-10-21
### Added
- Scope utility functions [#70](https://github.com/rokwire/core-auth-library-go/issues/70)

## [2.0.2] - 2022-08-18
### Added
- Automate tests [#4](https://github.com/rokwire/core-auth-library-go/issues/4)
### Changed
- Expose Request parsing functions [#65](https://github.com/rokwire/core-auth-library-go/issues/65)

## [2.0.1] - 2022-06-15
### Changed
- Update documentation [#62](https://github.com/rokwire/core-auth-library-go/issues/62)
- BREAKING: Service ID used as key ID in signatures [#49](https://github.com/rokwire/core-auth-library-go/issues/49)
- BREAKING: Handle service account access tokens [#35](https://github.com/rokwire/core-auth-library-go/issues/35)
- BREAKING: Add description to permission authorization policy model [#57](https://github.com/rokwire/core-auth-library-go/issues/57)
- Update documentation to reflect process for breaking changes and deprecations [#54](https://github.com/rokwire/core-auth-library-go/issues/54)
- BREAKING: Split AuthDataLoader interface [#36](https://github.com/rokwire/core-auth-library-go/issues/36)

### Added
- Add service account unit tests [#59](https://github.com/rokwire/core-auth-library-go/issues/59)

## [1.0.9] - 2022-04-27
### Fixed
- Service token is required to create RemoteAuthDataLoaderImpl [#50](https://github.com/rokwire/core-auth-library-go/issues/50)

## [1.0.8] - 2022-04-04
### Fixed
- Signature string is missing host and date headers [#45](https://github.com/rokwire/core-auth-library-go/issues/45)
### Added
- Define signature request struct to check signatures [#44](https://github.com/rokwire/core-auth-library-go/issues/44)

## [1.0.7] - 2022-03-24
### Added
- Add first party claim [#40](https://github.com/rokwire/core-auth-library-go/issues/40)
- Add system claim [#39](https://github.com/rokwire/core-auth-library-go/issues/39)
- Add support for signature auth to retrieve access tokens [#26](https://github.com/rokwire/core-auth-library-go/issues/26)

## [1.0.6] - 2022-03-03
### Changed
- Improve signature interfaces for request body [#29](https://github.com/rokwire/core-auth-library-go/issues/29)
### Fixed
- Content length header missing when signing request [#27](https://github.com/rokwire/core-auth-library-go/issues/27)
### Added
- Provide permanent claim for external ID [#24](https://github.com/rokwire/core-auth-library-go/issues/24)
- Add session ID claim [#32](https://github.com/rokwire/core-auth-library-go/issues/32)

## [1.0.5] - 2021-12-21
### Added
- Standardize fetching certain data from a remote auth service [#20](https://github.com/rokwire/core-auth-library-go/issues/20)
- Link service accounts to service registrations [#19](https://github.com/rokwire/core-auth-library-go/issues/19)

## [1.0.4] - 2021-12-03
### Added 
- Write unit tests for sigauth package [#17](https://github.com/rokwire/core-auth-library-go/pull/17)
- Check request signatures with any public key [#13](https://github.com/rokwire/core-auth-library-go/pull/13)

## [1.0.3] - 2021-11-23
### Added 
- Admin token claim [#15](https://github.com/rokwire/core-auth-library-go/issues/15)

## [1.0.2] - 2021-11-11
### Added
- Service token claim [#9](https://github.com/rokwire/core-auth-library-go/issues/9)
- Name in token claims [#7](https://github.com/rokwire/core-auth-library-go/issues/7)

## [1.0.1] - 2021-10-19
### Added
- Add an "authenticated" claim [#3](https://github.com/rokwire/core-auth-library-go/issues/3)

## [1.0.0] - 2021-10-01
### Added
- Initial release

[Unreleased]: https://github.com/rokwire/core-auth-library-go/compare/v3.2.1....HEAD
[3.2.1]: https://github.com/rokwire/core-auth-library-go/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/rokwire/core-auth-library-go/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/rokwire/core-auth-library-go/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/rokwire/core-auth-library-go/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/rokwire/core-auth-library-go/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/rokwire/core-auth-library-go/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/rokwire/core-auth-library-go/compare/v2.0.3...v2.1.0
[2.0.3]: https://github.com/rokwire/core-auth-library-go/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/rokwire/core-auth-library-go/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.9...v2.0.1
[1.0.9]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.8...v1.0.9
[1.0.8]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.7...v1.0.8
[1.0.7]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/rokwire/core-auth-library-go/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/rokwire/core-auth-library-go/tree/v1.0.0