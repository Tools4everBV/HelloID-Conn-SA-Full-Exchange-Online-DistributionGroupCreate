# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.1.0] - 13-05-2026

Enhanced form validation with Microsoft Graph API-based uniqueness checks for distribution group properties.

### Added

- New Entra ID-based validation datasources using Microsoft Graph API:
  - `EntraID-Check-DisplayName-Unique`: Validates display name uniqueness across distribution groups and mail-enabled security groups
  - `EntraID-Check-EmailAddress-Unique`: Validates email address (mail prefix + domain) uniqueness
  - `EntraID-Check-Alias-Unique`: Validates alias (mailNickname) uniqueness
- Each validation datasource includes proper error handling and user-friendly status messages ("Valid" or "Invalid" with details)

### Changed

- Replaced Exchange Online-based group name validation with comprehensive Microsoft Graph API validation checks
- Updated form datasource wiring to use new validation endpoints

### Removed

- Legacy Exchange Online-based validation datasource (`Distribution-Group-Create-check-names`)
- Legacy Exchange Online-based member/owner generation datasources (now using Microsoft Graph API for user retrieval)

## [2.0.0] - 13-05-2026

- Switched connector authentication to Microsoft Entra app-only certificate-based authentication for Exchange Online.

### Added

- New certificate-based Exchange Online connection flow in task and datasource scripts (import module, connect, and disconnect handling).
- New datasource resource files using updated naming convention, including `.config.json` files for:
	- check-names
	- members-generate-table
	- owners-generate-table
- Improved README content with setup guidance for Entra app registration, certificate configuration, and API/cmdlet references.

### Changed

- Refactored delegated form task to use app-only auth variables (`EntraIdOrganization`, `EntraIdAppId`, certificate inputs) and updated error/audit logging.
- Updated dynamic form configuration and related datasource wiring/UX text.
- Updated all-in-one setup script to align with V2.0 resource structure and conventions.

### Removed

- Legacy datasource files that used the previous naming/authentication approach.


## [1.0.0] - 13-07-2023

Initial release
