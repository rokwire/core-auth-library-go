# Conventions and Workflow
This document contains a description of the conventions and workflow process which should be followed when contributing to this repository. They are not final and suggestions are welcome.

## Conventions
- Variable naming should follow the camel-case convention in Go.
- Use snake-case everywhere in the database and JSON objects.

## Work Flow
This section describes the process that developers should follow when contributing to this repository.

### 1. Create issue
Create an issue for each new feature or bug. Issue names should describe the changes to be made starting with an action verb (eg. Set up project skeleton, Fix email login bug). Issues should contain a detailed description comment including any information about feature requirements or steps to reproduce bugs.

### 2. Create issue branch
All work should happen in an issue branch. The name of the branch should be `issues/ID-[issue number]`.

#### Update the CHANGELOG.md file
We should keep the changelog up to date as this is part of the open source platform. Each issue should be added to the top of the appropriate [verb](https://keepachangelog.com/en/1.0.0/#how) in the `[Unreleased]` section of the changelog in the corresponding issue branch in the format `{issue name} [#{issue-ID}]({issue url})` (eg. [Unreleased] Added - Set up project skeleton [#1](https://github.com/rokwire/core-building-block/issues/1))

#### Add code
Make as many commits as needed to complete the issue.

#### Write unit tests for your code
Whenever a new interface is created, a unit test must be created for each function it exposes. The purpose of these unit tests is primarily to ensure that the contract with consumers established by the interfaces are not unintentionally broken by future implementation changes. With this in mind, test cases should include all common usage, as well as any edge cases for which consistency is important. 

When updating or changing existing implementations, run the associated unit tests to ensure that they still pass. If they do not, the implementation changes likely changed the interface as well. If the change to the interface was intentional, update the unit tests as needed to make them pass and document the [Breaking Change](#breaking-changes). If the change was not intentional, rework your implementation changes to keep the interface consistent and ensure all tests pass.

### 3. Open Pull Request to `develop` branch
When ready, open a pull request to merge your issue branch into the `develop` branch. The name of the pull request should be `[ID-{the issue number}] {the issue name}`.
At least one reviewer must approve the changes before they are merged. 

If your PR resolves the issue entirely, link it to the issue in the description with a [keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) (eg. `Resolves #{issue number}`).This will close the issue automatically when the PR is merged. If the PR does not resolve the issue, include a reference to the related issue in the PR description without a keyword (eg. `Progress on #{issue number}`).

### 4. Merge the Pull Request
Once the pull request is approved, merge it into `develop` using "Squash and Merge". "Squash and Merge" merges all changes into `develop` in one single commit. This means that you can make as many commits as needed in your issue branch without cluttering the commit history on `develop`. When performing the "Squash and Mergs" you can exlude any low-impact commits from the description and leave only the ones which provide meaningful information.

### 5. Delete the issue branch
Delete the issue branch from GitHub

### 6. Close the issue in GitHub
If you have resolved the issues, verify that the issue has been closed by a pull request, or close it manually if not.

## Breaking Changes
Breaking changes should be avoided when possible, but will sometimes be necessary. In the event that a breaking change does need to be made, this change should be documented clearly for developers relying on the functionality. This includes the following items:
* Create and apply a "breaking" label to the associated issue in GitHub
* Add a "BREAKING:" prefix to the associated line in the CHANGELOG
* Document upgrade instructions in the README in the `Upgrading > Migration steps > Unreleased > Breaking changes` section. These should explain the changes that were made, as well as all changes the developer will need to make to handle the breaking change. Examples should be provided where appropriate.

When a release including the breaking change is created, the following steps must be taken:
* Update the MAJOR version number to indicate that incompatible interface changes have occurred (see [Semantic Versioning](https://semver.org/))
* Update the `Upgrading > Migration steps > Unreleased` section in the README to the latest version (eg. `Upgrading > Migration steps > v1.1.0`)
* Add a "BREAKING" warning to the release notes
* Include a copy of the upgrade instructions from the README in the release notes

## Deprecations
In some cases when [Breaking Changes](#breaking-changes) need to be made, the existing functionality must be maintained to provide backwards compatibility. To do so, the new component (function, type, field, package...) should be created and the old component should be maintained and flagged as deprecated. This will give time for developers relying on the component to make the necessary updates before it becomes unavailable. In these cases, the following process should be followed:
* Add a "DEPRECATED:" prefix to the associated line in the CHANGELOG
* Add a "Deprecated:" comment to the component and provide information about the deprecation and replacement. See the [Godoc](https://go.dev/blog/godoc) documentation for more information.
* Document upgrade instructions in the README in the `Upgrading > Migration steps > Unreleased > Deprecations` section. These should explain the changes that were made, as well as all changes the developer will need to make to replace the deprecated component. Examples should be provided where appropriate. If known, include a timeline for when the deprecated components will be removed.

When a release including the deprecation is created, the following steps must be taken:
* Update the `Upgrading > Migration steps > Unreleased` section in the README to the latest version (eg. `Upgrading > Migration steps > v1.1.0`)
* Include a copy of the upgrade instructions from the README in the release notes

When the deprecated components are finally removed, follow the process to document this as a [Breaking Change](#breaking-changes). 