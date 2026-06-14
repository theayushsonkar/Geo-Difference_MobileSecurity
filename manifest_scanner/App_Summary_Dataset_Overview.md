# Application Summary Dataset (`manifest_apps.csv`)

## Purpose

This dataset is the primary output of the manifest analysis stage.

Unlike the other datasets, which store detailed information about individual permissions, components, SDKs, or network rules, this dataset stores **one summarized record per application**.

Each row represents **one application sample** and contains aggregated features extracted from the AndroidManifest.xml and related resources.

The goal of this dataset is to provide a compact, analysis-ready representation of each application without requiring joins across multiple detailed datasets for common comparisons.

---

## Metadata Fields

### `run_id`

**What it stores:**
Identifier of the extraction run.

**Why it is stored:**
Helps track which execution of the tool generated the record.

---

### `schema_version`

**What it stores:**
Version of the dataset schema.

**Why it is stored:**
Ensures future versions of the dataset remain interpretable and comparable.

---

### `parser_version`

**What it stores:**
Version of the extractor used to generate the record.

**Why it is stored:**
Allows identification of the extraction logic that produced the result.

---

## Sample Identification Fields

### `sample_id`

**What it stores:**
Unique identifier assigned to the application sample.

**Why it is stored:**
Acts as the primary key for the dataset and is used to connect records across all other datasets.

---

### `package_name`

**What it stores:**
Normalized package name assigned during extraction.

**Why it is stored:**
Provides a consistent application identifier across all datasets.

---

### `manifest_package_name`

**What it stores:**
Package name declared directly inside the AndroidManifest.xml.

**Why it is stored:**
Allows validation that extraction and normalization were performed correctly.

---

### `apk_sha256`

**What it stores:**
SHA-256 hash of the analyzed APK.

**Why it is stored:**
Provides a unique identifier for the application binary and allows comparison of APKs collected from different countries, stores, or time periods.

This is one of the most important fields for identifying whether two samples are actually the same binary.

---

### `manifest_sha256`

**What it stores:**
SHA-256 hash of the extracted AndroidManifest.xml.

**Why it is stored:**
Allows comparison of manifest files independently from the APK itself.

This makes it possible to detect manifest-level differences even when applications share the same package name.

---

## Collection Metadata

### `app_country_code`

**What it stores:**
Country label assigned to the application sample.

Examples:

```text
IN
US
BR
CN
```

**Why it is stored:**
Allows applications to be grouped and compared across countries.

---

### `app_country_name`

**What it stores:**
Human-readable country name.

Examples:

```text
India
United States
Brazil
China
```

**Why it is stored:**
Improves readability during analysis and reporting.

---

### `app_region_group`

**What it stores:**
Higher-level geographical region assigned to the application.

Examples:

```text
south_asia
east_asia
eu_member
```

**Why it is stored:**
Allows broader regional comparisons.

---

### `app_store`

**What it stores:**
Store or marketplace from which the application was collected.

Examples:

```text
Google Play
Huawei AppGallery
APKPure
```

**Why it is stored:**
Different stores may distribute different versions of the same application.

---

### `collection_batch`

**What it stores:**
Identifier of the collection batch.

**Why it is stored:**
Provides traceability regarding when and how the sample was collected.

---

## Extraction Status Fields

### `source_path`

**What it stores:**
Original file path used during extraction.

**Why it is stored:**
Provides traceability to the analyzed sample.

---

### `has_manifest`

**What it stores:**
Whether a manifest file was successfully extracted.

**Why it is stored:**
Indicates whether manifest-based analysis was possible.

---

### `has_smali`

**What it stores:**
Whether application code (smali) was extracted.

**Why it is stored:**
Provides visibility into available static-analysis artifacts.

---

### `has_native_libs`

**What it stores:**
Whether native libraries were found.

**Why it is stored:**
Indicates the presence of native code components.

---

### `has_res_xml`

**What it stores:**
Whether XML resource files were extracted.

**Why it is stored:**
Network security configuration analysis depends on resource XML files.

---

## Application Version Information

### `version_code`

**What it stores:**
Internal application version code.

**Why it is stored:**
Used to distinguish different releases of the application.

---

### `version_name`

**What it stores:**
Human-readable application version.

**Why it is stored:**
Provides an easily recognizable version identifier.

---

### `compile_sdk`

**What it stores:**
Android SDK version used during compilation.

**Why it is stored:**
Provides insight into the Android platform version used during development.

---

### `uses_sdk_present`

**What it stores:**
Whether the manifest contains a `<uses-sdk>` element.

**Why it is stored:**
Indicates whether SDK information was explicitly declared.

---

### `min_sdk`

**What it stores:**
Minimum Android version supported by the application.

**Why it is stored:**
Defines the oldest Android version on which the application can run.

---

### `target_sdk`

**What it stores:**
Target Android SDK version.

**Why it is stored:**
Many Android security behaviors depend on the target SDK version.

---

### `install_location`

**What it stores:**
Preferred installation location.

**Why it is stored:**
Preserves installation preferences declared by the application.

---

### `app_category`

**What it stores:**
Category assigned to the application.

**Why it is stored:**
Allows grouping applications by functionality.

---

## Application Configuration Fields

### `debuggable`

**What it stores:**
Whether the application is configured as debuggable.

**Why it is stored:**
Indicates whether debugging features are enabled.

---

### `extract_native_libs`

**What it stores:**
Value of `android:extractNativeLibs`.

**Why it is stored:**
Captures native library packaging behavior.

---

### `hardware_accelerated`

**What it stores:**
Value of `android:hardwareAccelerated`.

**Why it is stored:**
Captures rendering configuration declared by the application.

---

### `network_security_config_present`

**What it stores:**
Whether a custom Network Security Configuration is present.

**Why it is stored:**
Indicates whether the application defines custom network trust rules.

---

## Manifest Structure Summary

### `uses_libraries_count`

**What it stores:**
Number of `<uses-library>` declarations.

**Why it is stored:**
Provides a summary of shared library dependencies declared in the manifest.

---

### `uses_feature_count`

**What it stores:**
Number of `<uses-feature>` declarations.

**Why it is stored:**
Captures the number of hardware and software features referenced by the application.

---

### `uses_feature_required_count`

**What it stores:**
Number of required features.

**Why it is stored:**
Indicates how many declared features are mandatory.

---

### `instrumentation_count`

**What it stores:**
Number of instrumentation declarations.

**Why it is stored:**
Captures testing or instrumentation components declared in the application.

---

### `activity_alias_count`

**What it stores:**
Number of activity aliases.

**Why it is stored:**
Provides insight into alternative activity entry points.

---

## Shared User and Backup Configuration

### `shared_user_id`

**What it stores:**
Value of `android:sharedUserId`.

**Why it is stored:**
Preserves the exact shared user identifier if present.

---

### `has_shared_user_id`

**What it stores:**
Whether a shared user ID is configured.

**Why it is stored:**
Allows quick identification of applications using shared UID functionality.

---

### `backup_agent_class`

**What it stores:**
Custom backup agent class.

**Why it is stored:**
Preserves backup-handler configuration.

---

### `full_backup_content_present`

**What it stores:**
Whether `fullBackupContent` is configured.

**Why it is stored:**
Indicates the presence of custom backup rules.

---

### `data_extraction_rules_present`

**What it stores:**
Whether `dataExtractionRules` are configured.

**Why it is stored:**
Captures modern Android backup configuration.

---

## Backup and Cleartext Settings

### `allow_backup_present`

**What it stores:**
Whether `android:allowBackup` was explicitly declared.

**Why it is stored:**
Distinguishes between explicit and default backup configuration.

---

### `allow_backup_value`

**What it stores:**
Raw value of `android:allowBackup` from the manifest.

**Why it is stored:**
Preserves the original declared value.

---

### `allow_backup_effective`

**What it stores:**
Final backup setting after applying Android defaults.

**Why it is stored:**
Represents whether backup is effectively enabled.

---

### `allow_backup_effective_source`

**What it stores:**
Reason used to determine the effective backup value.

**Why it is stored:**
Makes the backup-state calculation transparent and reproducible.

---

### `cleartext_global_explicit`

**What it stores:**
Whether `android:usesCleartextTraffic` was explicitly declared.

**Why it is stored:**
Distinguishes between explicit and default cleartext policy.

---

### `cleartext_global_default`

**What it stores:**
Default cleartext policy when not explicitly declared.

**Why it is stored:**
Provides the Android default behavior as a baseline.

---

### `cleartext_global_effective_manifest`

**What it stores:**
Effective cleartext policy after applying manifest-level rules.

**Why it is stored:**
Represents the application's actual cleartext traffic behavior.

---

### `cleartext_global_effective_manifest_source`

**What it stores:**
Reason used to determine the effective cleartext value.

**Why it is stored:**
Makes the cleartext policy calculation transparent.

---

### `cleartext_attr_ignored_on_target38_plus`

**What it stores:**
Whether the cleartext attribute is ignored due to target SDK >= 28.

**Why it is stored:**
Android 9+ ignores the manifest cleartext attribute when target SDK is 28 or higher.

---

## Permission Summary Fields

These values are aggregated from the permission dataset.

### `requested_permission_total`

**What it stores:**
Total number of permission requests (including duplicates).

**Why it is stored:**
Provides a raw count of requested permissions.

---

### `requested_permission_unique`

**What it stores:**
Number of unique permission names requested.

**Why it is stored:**
Represents the distinct set of permissions the application asks for.

---

### `requested_permission_dangerous_unique`

**What it stores:**
Number of unique dangerous permissions requested.

**Why it is stored:**
Dangerous permissions require runtime user consent on modern Android.

---

### `requested_permission_other_unique`

**What it stores:**
Number of unique permissions not mapped into known families.

**Why it is stored:**
Captures permissions that fall outside standard categories.

---

### `perm_location`

**What it stores:**
Count of location-related permissions requested.

**Why it is stored:**
Summarizes location capability requests.

---

### `perm_contacts`

**What it stores:**
Count of contacts-related permissions requested.

**Why it is stored:**
Summarizes contacts access requests.

---

### `perm_camera_mic`

**What it stores:**
Count of camera and microphone permissions requested.

**Why it is stored:**
Summarizes sensor access requests.

---

### `perm_storage`

**What it stores:**
Count of storage-related permissions requested.

**Why it is stored:**
Summarizes file system access requests.

---

### `perm_network`

**What it stores:**
Count of network-related permissions requested.

**Why it is stored:**
Summarizes network access requests.

---

### `perm_bluetooth`

**What it stores:**
Count of Bluetooth-related permissions requested.

**Why it is stored:**
Summarizes Bluetooth capability requests.

---

### `declared_permission_count`

**What it stores:**
Number of custom permissions declared.

**Why it is stored:**
Indicates the application defines its own access control mechanisms.

---

### `declared_permission_group_count`

**What it stores:**
Number of permission groups declared.

**Why it is stored:**
Groups organize related permissions.

---

### `declared_permission_tree_count`

**What it stores:**
Number of permission trees declared.

**Why it is stored:**
Permission trees define dynamic permission namespaces.

---

### `declared_signature_permission_count`

**What it stores:**
Number of custom permissions with signature protection level.

**Why it is stored:**
Signature permissions are only grantable to same-signed applications.

---

### `declared_normal_permission_count`

**What it stores:**
Number of custom permissions with normal protection level.

**Why it is stored:**
Normal permissions are granted automatically.

---

### `declared_custom_permission_count`

**What it stores:**
Number of application-defined permissions.

**Why it is stored:**
Summarizes all custom permission declarations.

---

## Privacy Sandbox Summary

### `ps_topics`

**What it stores:**
Indicates use of the Topics API.

**Why it is stored:**
Captures adoption of Privacy Sandbox interest-based advertising APIs.

---

### `ps_attribution`

**What it stores:**
Indicates use of the Attribution API.

**Why it is stored:**
Captures adoption of Privacy Sandbox conversion measurement APIs.

---

### `ps_custom_audience`

**What it stores:**
Indicates use of the Custom Audience API.

**Why it is stored:**
Captures adoption of Privacy Sandbox remarketing APIs.

---

### `ps_ad_id`

**What it stores:**
Indicates use of the Privacy Sandbox advertising identifier APIs.

**Why it is stored:**
Captures adoption of Privacy Sandbox ad ID APIs.

---

## Component Summary Fields

These values are aggregated from the component dataset.

### `component_total`

**What it stores:**
Total number of Android components declared.

**Why it is stored:**
Provides a measure of application complexity from a component perspective.

---

### `activity_count`

**What it stores:**
Number of activities declared.

**Why it is stored:**
Activities represent user-interactive screens.

---

### `service_count`

**What it stores:**
Number of services declared.

**Why it is stored:**
Services perform background operations.

---

### `receiver_count`

**What it stores:**
Number of broadcast receivers declared.

**Why it is stored:**
Receivers respond to system or application broadcasts.

---

### `provider_count`

**What it stores:**
Number of content providers declared.

**Why it is stored:**
Providers manage structured data access.

---

### `exported_activities`

**What it stores:**
Number of activities that are effectively exported.

**Why it is stored:**
Exported activities can be launched by other applications.

---

### `exported_services`

**What it stores:**
Number of services that are effectively exported.

**Why it is stored:**
Exported services can be bound or started by other applications.

---

### `exported_receivers`

**What it stores:**
Number of broadcast receivers that are effectively exported.

**Why it is stored:**
Exported receivers can receive broadcasts from other applications.

---

### `exported_providers`

**What it stores:**
Number of content providers that are effectively exported.

**Why it is stored:**
Exported providers can be queried or modified by other applications.

---

### `exported_receivers_no_perm`

**What it stores:**
Number of exported receivers without permission protection.

**Why it is stored:**
Receivers exported without permissions may receive unexpected broadcasts.

---

### `android12_exported_missing_count`

**What it stores:**
Number of components that violate Android 12 exported declaration requirements.

**Why it is stored:**
Android 12 requires explicit exported declarations for components with intent filters.

---

### `exported_components_with_intent_filter`

**What it stores:**
Number of exported components that contain intent filters.

**Why it is stored:**
Intent filters define how components can be invoked externally.

---

### `exported_components_with_custom_scheme`

**What it stores:**
Number of exported components that handle custom URI schemes.

**Why it is stored:**
Custom schemes are commonly used for deep linking and inter-app communication.

---

### `deep_link_total`

**What it stores:**
Total number of deep link declarations.

**Why it is stored:**
Provides a measure of deep linking surface area.

---

### `deep_link_custom_scheme_count`

**What it stores:**
Number of deep links using custom URI schemes.

**Why it is stored:**
Custom schemes can be invoked by any application.

---

### `deep_link_https_count`

**What it stores:**
Number of HTTPS deep link handlers.

**Why it is stored:**
HTTPS deep links support Android App Links with verification.

---

### `deep_link_http_count`

**What it stores:**
Number of HTTP deep link handlers.

**Why it is stored:**
HTTP deep links are less secure and not recommended for modern apps.

---

### `deep_link_market_count`

**What it stores:**
Number of market URI handlers.

**Why it is stored:**
Market URIs are used for store and purchase intents.

---

## SDK Summary Fields

These values are aggregated from the SDK dataset.

### `sdk_detected_count`

**What it stores:**
Total number of SDKs detected.

**Why it is stored:**
Provides a measure of third-party library usage.

---

### `sdk_china_count`

**What it stores:**
Number of SDKs originating from China.

**Why it is stored:**
Captures geographic origin of software dependencies.

---

### `sdk_usa_count`

**What it stores:**
Number of SDKs originating from the United States.

**Why it is stored:**
Captures geographic origin of software dependencies.

---

### `sdk_india_count`

**What it stores:**
Number of SDKs originating from India.

**Why it is stored:**
Captures geographic origin of software dependencies.

---

### `sdk_israel_count`

**What it stores:**
Number of SDKs originating from Israel.

**Why it is stored:**
Captures geographic origin of software dependencies.

---

### `sdk_eu_count`

**What it stores:**
Number of SDKs originating from the European Union.

**Why it is stored:**
Captures geographic origin of software dependencies.

---

### `sdk_other_count`

**What it stores:**
Number of SDKs from other regions not otherwise categorized.

**Why it is stored:**
Ensures complete coverage of geographic origin.

---

### `sdk_ad_network_count`

**What it stores:**
Number of advertising network SDKs detected.

**Why it is stored:**
Summarizes monetization through ads.

---

### `sdk_analytics_count`

**What it stores:**
Number of analytics SDKs detected.

**Why it is stored:**
Summarizes user behavior tracking.

---

### `sdk_attribution_count`

**What it stores:**
Number of attribution SDKs detected.

**Why it is stored:**
Summarizes marketing campaign measurement.

---

### `sdk_social_count`

**What it stores:**
Number of social media SDKs detected.

**Why it is stored:**
Summarizes social platform integrations.

---

### `sdk_game_engine_count`

**What it stores:**
Number of game engine SDKs detected.

**Why it is stored:**
Identifies applications built with game engines.

---

## Network Security Summary

These values are aggregated from the network security dataset.

### `netcfg_main_cleartext_global`

**What it stores:**
Application-wide cleartext traffic policy from main configuration.

**Why it is stored:**
Summarizes global HTTP allowance.

---

### `netcfg_cleartext_exception_count`

**What it stores:**
Number of domain-specific cleartext exceptions.

**Why it is stored:**
Indicates how many domains are allowed to use HTTP.

---

### `netcfg_pinned_domain_count`

**What it stores:**
Number of domains with certificate pinning configured.

**Why it is stored:**
Summarizes use of certificate pinning.

---

### `netcfg_trust_user_certs_production`

**What it stores:**
Whether user-installed certificates are trusted in production configuration.

**Why it is stored:**
Trusting user certificates can weaken TLS security.

---

### `netcfg_has_debug_overrides`

**What it stores:**
Whether debug-specific network rules exist.

**Why it is stored:**
Debug overrides may alter network behavior in development builds.

---

### `netcfg_main_config_found`

**What it stores:**
Whether a primary Network Security Configuration file was found.

**Why it is stored:**
Indicates the presence of a main network configuration.

---

### `netcfg_additional_config_count`

**What it stores:**
Number of additional Network Security Configuration files discovered.

**Why it is stored:**
Multiple config files may contain overlapping or supplementary rules.

---

## Hardcoded Value Summary

### `secret_public_id_count`

**What it stores:**
Count of public identifiers such as advertising IDs.

**Why it is stored:**
Summarizes presence of user-resettable identifiers.

---

### `secret_sensitive_token_count`

**What it stores:**
Count of potentially sensitive tokens or API keys.

**Why it is stored:**
Provides an indicator of hardcoded credentials requiring review.

---

### `secret_possible_credential_count`

**What it stores:**
Count of potential credential-like values requiring further review.

**Why it is stored:**
Highlights values that may be authentication secrets.

---

## Package Visibility Summary

### `queries_package_count`

**What it stores:**
Number of package visibility declarations.

**Why it is stored:**
Summarizes which other packages the application can discover.

---

### `queries_intent_count`

**What it stores:**
Number of intent visibility declarations.

**Why it is stored:**
Summarizes which intent patterns the application can resolve.

---

### `queries_provider_count`

**What it stores:**
Number of provider visibility declarations.

**Why it is stored:**
Summarizes which content providers the application can interact with.

---

## Extraction Status Fields

### `extraction_status`

**What it stores:**
Overall extraction result.

**Why it is stored:**
Indicates whether processing completed successfully.

---

### `warnings`

**What it stores:**
Non-fatal issues encountered during extraction.

**Why it is stored:**
Provides visibility into potential data-quality issues.

---

### `errors`

**What it stores:**
Fatal extraction errors.

**Why it is stored:**
Documents failures encountered during processing.

---

### `notes`

**What it stores:**
Additional parser-generated information.

**Why it is stored:**
Provides supplementary context that may be useful during debugging or validation.

---

## Summary

This dataset is the primary output of the manifest analysis stage. It combines and summarizes information extracted from permissions, components, SDKs, network security configurations, backup settings, deep links, Privacy Sandbox declarations, and application metadata into a single application-level record.

While the other datasets provide detailed evidence, this dataset provides a compact overview of each application and serves as the main analysis-ready representation of the application's manifest configuration.