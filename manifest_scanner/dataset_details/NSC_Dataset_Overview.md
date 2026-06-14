# Network Security Configuration Dataset (`manifest_network_domains.csv`)

## Purpose

This dataset stores information extracted from Android Network Security Configuration (NSC) files referenced by the application's `AndroidManifest.xml` or discovered within the application's resources.

Each row in this dataset represents **one network security rule** extracted from a Network Security Configuration file.

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
Used to connect network configuration information with all other datasets generated from the same application.

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
Allows network security configurations to be grouped and compared across countries.

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

## Network Rule Identification Fields

### `network_rule_id`

**What it stores:**
Unique identifier assigned to the network security rule.

**Why it is stored:**
Provides a stable reference for each extracted rule and prevents duplicate records.

---

## Configuration Source Fields

These fields describe where the network rule originated.

---

### `config_file`

**What it stores:**
Name of the XML file containing the rule.

Example:

```text
network_security_config.xml
```

**Why it is stored:**
Allows the rule to be traced back to the exact configuration file from which it was extracted.

Some applications may contain multiple network security configuration files, so keeping the file name helps preserve context.

---

### `config_scope`

**What it stores:**
Role of the configuration file.

Possible values:

```text
main
additional
sdk_embedded
```

**Why it is stored:**
Not all configuration files serve the same purpose.

For example:

* A main configuration file may define the application's network policy.
* Additional configuration files may contain supplementary rules.
* SDK-embedded configurations may be included by third-party libraries.

This field helps preserve that distinction.

---

### `config_source`

**What it stores:**
How the configuration file was discovered.

Possible values:

```text
manifest_reference
xml_scan
```

**Why it is stored:**
A configuration file can be discovered in two ways:

1. Directly referenced by the AndroidManifest.xml.
2. Found by scanning XML files within the application resources.

This field preserves how the file was identified.

---

## Rule Definition Fields

These fields describe the actual network security rule.

---

### `rule_type`

**What it stores:**
Type of network security rule.

Examples:

```text
base-config
domain-config
pin-set
debug-overrides
```

**Why it is stored:**
Different rule types affect network behavior in different ways.

For example:

* `base-config` applies globally.
* `domain-config` applies only to specific domains.
* `pin-set` defines certificate pinning rules.
* `debug-overrides` define development-time exceptions.

---

## Domain Configuration Fields

### `domain`

**What it stores:**
Domain to which the rule applies.

Example:

```text
example.com
```

**Why it is stored:**
Some network security rules apply only to specific domains. This field records the affected domain.

---

### `include_subdomains`

**What it stores:**
Whether subdomains are included in the rule.

Examples:

```text
True
False
```

**Why it is stored:**
A rule may apply only to:

```text
example.com
```

or to:

```text
*.example.com
```

This field captures that difference.

---

## Cleartext Traffic Fields

### `cleartext_permitted`

**What it stores:**
Whether unencrypted HTTP traffic is allowed.

Examples:

```text
True
False
```

**Why it is stored:**
Android applications can choose whether to allow cleartext (HTTP) communication.

This field records the policy declared by the application.

Example:

```xml
<base-config cleartextTrafficPermitted="true">
```

would be stored as:

```text
cleartext_permitted = True
```

---

## Trust Anchor Fields

### `trust_anchor_src`

**What it stores:**
Certificate sources trusted by the application.

Examples:

```text
system
user
system;user
```

**Why it is stored:**
Android can trust:

* System certificate authorities.
* User-installed certificate authorities.

The choice of trust anchors directly affects how TLS certificates are validated.

This field records which certificate stores are trusted.

---

## Certificate Pinning Fields

### `pin_digest`

**What it stores:**
Certificate pin value defined in a pin set.

Usually a SHA-256 digest.

**Why it is stored:**
Certificate pinning restricts which certificates are accepted when establishing TLS connections.

This field preserves the actual pin value declared by the application.

---

### `override_pins`

**What it stores:**
Whether certificate pinning can be overridden.

Examples:

```text
True
False
```

**Why it is stored:**
Android allows certain trust-anchor configurations to bypass certificate pinning.

This field records whether such behavior is enabled.

---

## Debug Configuration Fields

### `is_debug_override`

**What it stores:**
Whether the rule originates from a `<debug-overrides>` section.

**Why it is stored:**
Debug-only rules are intended for development and testing environments.

They should be distinguished from production network policies.

---

### `applies_when_debuggable`

**What it stores:**
Whether the rule applies only when the application is running in debuggable mode.

Examples:

```text
True
False
```

**Why it is stored:**
Some network security exceptions are only active during development.

This field captures whether the rule depends on the application's debuggable state.

---

## Example

Consider the following configuration:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>
    </trust-anchors>
</base-config>

<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">
        127.0.0.1
    </domain>
</domain-config>
```

This would produce two records:

### Record 1

```text
rule_type = base-config
cleartext_permitted = True
trust_anchor_src = system;user
```

### Record 2

```text
rule_type = domain-config
domain = 127.0.0.1
include_subdomains = True
cleartext_permitted = True
```

---

## Summary

It captures:

* Whether cleartext HTTP traffic is allowed.
* Which domains have special network rules.
* Which certificate authorities are trusted.
* Whether certificate pinning is used.
* Whether network behavior changes in debug mode.
* Where network security rules originate.