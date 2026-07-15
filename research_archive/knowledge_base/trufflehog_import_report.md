# TruffleHog Secret Knowledge Acquisition Report

- **Repository**: https://github.com/trufflesecurity/trufflehog.git
- **Commit Hash**: `d7dcc6d3fe80206bc1bdcfb15db1dd8d890956fd`
- **Import Timestamp**: 2026-07-08T09:36:51.731605+00:00

## Statistics
- **Detectors Imported**: 907
- **Regex Extracted**: 1115
- **Discarded Helper Regexes**: 98
- **Discarded Verification Regexes**: 0
- **Duplicate Regex Removed**: 184
- **Final Unique Patterns**: 931

## Verification-Supported Statistics
- **Verified**: 927
- **Unverified**: 4

## Top 10 Provider Distribution
- **Azure**: 19
- **Open**: 6
- **Salesforce**: 6
- **Slack**: 6
- **Api**: 4
- **AWS**: 4
- **Bitbucket**: 4
- **Box**: 4
- **Get**: 4
- **Stripe**: 4

## Top 10 Secret Type Distribution
- **API Key**: 521
- **IO API Key**: 17
- **API API Key**: 11
- **Stack API Key**: 10
- **Token**: 10
- **Api Key**: 9
- **Api API Key**: 7
- **Sas Token**: 7
- **CRM API Key**: 7
- **Personal Access Token**: 6

## Known Limitations
- **Regex Extraction**: Some highly dynamic regexes generated via complex Go AST or `Sprintf` logic cannot be extracted statically and might be missed or malformed.
- **Comments**: String literals containing `//` require strict multi-line AST parsing, our regex-based comment-stripper gracefully skips lines beginning with comments to prevent corruption.

The importer preserves TruffleHog RE2 expressions verbatim rather than translating them into Python regex.
