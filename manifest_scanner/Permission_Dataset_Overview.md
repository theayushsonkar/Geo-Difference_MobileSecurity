# Permission Dataset (`manifest_permissions.csv`)

## Purpose

This dataset stores all permission-related declarations found in the application's `AndroidManifest.xml`.

In addition to requesting Android permissions, applications can also define their own custom permissions. Therefore, this dataset captures both:

* Permissions requested by the application.
* Permissions declared by the application.

Each row in this dataset represents **one permission-related entry** extracted from the manifest.

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

## Application Identification Fields

### `sample_id`

**What it stores:**
Unique identifier assigned to the application sample.

**Why it is stored:**
Used to connect permission information with all other datasets generated from the same application.

---

### `package_name`

**What it stores:**
Android package name of the application.

Example:

```text
com.ecffri.arrows
```

**Why it is stored:**
Provides a human-readable identifier for the application.

---

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
Allows permissions to be grouped and compared across countries.

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

## Permission Identification Fields

### `permission_id`

**What it stores:**
Unique identifier assigned to the permission record.

**Why it is stored:**
Provides a stable reference for each permission entry and prevents duplicate records.

---

### `record_type`

**What it stores:**
Type of permission declaration found in the manifest.

Examples:

```text
uses-permission
permission
permission-group
permission-tree
uses-permission-sdk-23
```

**Why it is stored:**
Not all permission entries serve the same purpose.

For example:

```xml
<uses-permission android:name="android.permission.CAMERA"/>
```

means the application is requesting camera access.

Whereas:

```xml
<permission android:name="com.example.MY_PERMISSION"/>
```

means the application is defining its own permission.

This field preserves that distinction.

---

### `permission_name`

**What it stores:**
Full permission name.

Examples:

```text
android.permission.CAMERA
android.permission.ACCESS_FINE_LOCATION
com.ecffri.arrows.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
```

**Why it is stored:**
This is the actual permission being analyzed and represents the capability or access-control mechanism associated with the application.

---

### `permission_namespace`

**What it stores:**
Namespace to which the permission belongs.

Examples:

```text
android
custom
```

**Why it is stored:**
Helps distinguish Android platform permissions from application-defined permissions.

---

## Permission Classification Fields

### `family`

**What it stores:**
Functional category assigned to the permission.

Examples:

```text
perm_location
perm_network
perm_contacts
perm_camera_mic
perm_storage
perm_bluetooth
perm_biometric
perm_other
```

**Why it is stored:**
Analyzing hundreds of individual permissions becomes difficult at scale.

Grouping permissions into families makes it easier to understand what types of resources an application is requesting.

For example:

```text
ACCESS_FINE_LOCATION
ACCESS_COARSE_LOCATION
```

both belong to:

```text
perm_location
```

---

### `is_android_standard`

**What it stores:**
Indicates whether the permission belongs to the Android operating system.

Examples:

```text
android.permission.CAMERA
android.permission.INTERNET
android.permission.ACCESS_FINE_LOCATION
```

would be marked as:

```text
is_android_standard = True
```

**Why it is stored:**
Android applications can use both:

1. Permissions provided by Android itself.
2. Permissions created by app developers.

This field helps distinguish between permissions that are part of the Android platform and permissions that originate from the application or another vendor.

Android permissions generally represent standard device capabilities such as camera, location, contacts, storage, notifications, and network access.

---

### `is_custom`

**What it stores:**
Indicates whether the permission was created and defined by the application itself.

Example:

```xml
<permission
    android:name="com.ecffri.arrows.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
    android:protectionLevel="signature"/>
```

would be marked as:

```text
is_custom = True
```

**Why it is stored:**
Applications can define their own permissions to protect internal components such as activities, services, receivers, or content providers.

These permissions act as application-specific access control mechanisms and provide insight into how the application manages access to its internal functionality.

---

## Permission Protection Fields

### `protection_level`

**What it stores:**
Protection level assigned to a declared permission.

Examples:

```text
normal
dangerous
signature
privileged
```

**Why it is stored:**
Protection levels determine how a permission can be granted.

For example:

```text
signature
```

means only applications signed by the same developer can obtain that permission.

This field helps understand the strength of application-defined access controls.

---

### `label_present`

**What it stores:**
Whether a label is defined for the permission.

**Why it is stored:**
Permissions intended for use by other applications are often documented with labels. This field captures whether such documentation exists.

---

### `description_present`

**What it stores:**
Whether a description is defined for the permission.

**Why it is stored:**
Descriptions provide additional context about the purpose of a custom permission.

This field helps characterize how thoroughly custom permissions are documented.

---

## Source Tracking Fields

### `source_element`

**What it stores:**
Manifest element from which the permission was extracted.

Examples:

```text
uses-permission
permission
uses-permission-sdk-23
```

**Why it is stored:**
Preserves the exact XML element that generated the record.

---

### `source_xml`

**What it stores:**
XML file from which the permission was extracted.

**Why it is stored:**
Provides traceability back to the original source file.

---

## Privacy Sandbox Field

### `is_privacy_sandbox_permission`

**What it stores:**
Indicates whether the permission belongs to Android Privacy Sandbox APIs.

Examples:

```text
android.permission.ACCESS_ADSERVICES_TOPICS
android.permission.ACCESS_ADSERVICES_AD_ID
android.permission.ACCESS_ADSERVICES_ATTRIBUTION
```

**Why it is stored:**
Android is introducing Privacy Sandbox APIs as an alternative to traditional advertising identifiers and tracking mechanisms.

This field makes it easy to identify applications that have adopted these newer APIs.

---

## Notes Field

### `notes`

**What it stores:**
Additional parser-generated information related to the permission.

Examples:

```text
custom_permission
privacy_sandbox
unknown_family
```

**Why it is stored:**
Provides supplementary context without requiring additional dataset columns.

It can also help during validation and debugging of extraction results.

---

## Summary

It captures:

* What permissions the application requests.
* What permissions the application defines.
* How permissions are categorized.
* Whether permissions belong to Android or are application-defined.
* Protection levels of custom permissions.
* Adoption of Android Privacy Sandbox permissions.
