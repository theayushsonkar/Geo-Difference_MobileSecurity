"""
Output column definitions, type sets, defaults, and row normalization.

Column order is frozen.
"""

from typing import Any, Dict, List

from .constants import ALL_FAMILIES, SDK_CATEGORIES


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT COLUMN SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

APP_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "manifest_package_name", "app_country_code", "app_country_name", "app_region_group",
    "app_store", "collection_batch", "apk_sha256", "source_path", "has_manifest",
    "has_smali", "has_native_libs", "has_res_xml", "manifest_sha256",
    "version_code", "version_name", "compile_sdk", "uses_sdk_present", "min_sdk",
    "target_sdk", "install_location", "app_category", "debuggable",
    "extract_native_libs", "hardware_accelerated", "network_security_config_present",
    "uses_libraries_count", "uses_feature_count", "uses_feature_required_count",
    "instrumentation_count", "activity_alias_count", "shared_user_id",
    "has_shared_user_id", "backup_agent_class", "full_backup_content_present",
    "data_extraction_rules_present", "allow_backup_present", "allow_backup_value",
    "allow_backup_effective", "allow_backup_effective_source",
    "cleartext_global_explicit", "cleartext_global_default",
    "cleartext_global_effective_manifest", "cleartext_global_effective_manifest_source",
    "cleartext_attr_ignored_on_target38_plus", "requested_permission_total",
    "requested_permission_unique", "requested_permission_dangerous_unique",
    "requested_permission_other_unique", *ALL_FAMILIES, "declared_permission_count",
    "declared_permission_group_count", "declared_permission_tree_count",
    "declared_signature_permission_count", "declared_normal_permission_count",
    "declared_custom_permission_count", "ps_topics", "ps_attribution",
    "ps_custom_audience", "ps_ad_id", "component_total", "activity_count",
    "service_count", "receiver_count", "provider_count", "exported_activities",
    "exported_services", "exported_receivers", "exported_providers",
    "exported_receivers_no_perm", "android12_exported_missing_count",
    "exported_components_with_intent_filter", "exported_components_with_custom_scheme",
    "deep_link_total", "deep_link_custom_scheme_count", "deep_link_https_count",
    "deep_link_http_count", "deep_link_market_count", "sdk_detected_count",
    "sdk_china_count", "sdk_usa_count", "sdk_india_count", "sdk_israel_count",
    "sdk_eu_count", "sdk_other_count", *[f"sdk_{cat}_count" for cat in SDK_CATEGORIES],
    "netcfg_main_cleartext_global", "netcfg_cleartext_exception_count",
    "netcfg_pinned_domain_count", "netcfg_trust_user_certs_production",
    "netcfg_has_debug_overrides", "netcfg_main_config_found",
    "netcfg_additional_config_count", "secret_public_id_count",
    "secret_sensitive_token_count", "secret_possible_credential_count",
    "queries_package_count", "queries_intent_count", "queries_provider_count",
    "extraction_status", "warnings", "errors", "notes",
]

SDK_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "app_country_code", "app_region_group", "sdk_id", "sdk_name", "sdk_prefix",
    "sdk_version", "sdk_version_source", "sdk_version_confidence",
    "sdk_ecosystem", "sdk_identifier", "sdk_category", "vendor_country_code",
    "vendor_region_group", "detected_manifest", "detected_smali",
    "detected_native", "detected_strings", "detection_source_primary",
    "evidence_type", "evidence_value", "evidence_count",
]

STATIC_CODE_FINDINGS_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "app_country_code", "app_region_group", "finding_id", "finding_type",
    "finding_subtype", "normalized_value", "finding_confidence",
    "occurrence_count", "source_file_count", "source_layer", "source_file",
    "evidence_snippet", "finding_metadata",
]

COMPONENT_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "app_country_code", "app_region_group", "component_id", "component_type",
    "component_name", "component_name_format", "source_xml", "enabled_explicit_present",
    "enabled_explicit_value", "enabled_effective", "exported_explicit_present",
    "exported_explicit_value", "has_intent_filter", "intent_filter_count",
    "action_count", "category_count", "data_count", "custom_scheme_count",
    "http_scheme_count", "https_scheme_count", "market_scheme_count",
    "other_scheme_count", "is_launcher", "is_browsable", "has_permission_guard",
    "permission_name", "direct_boot_aware", "isolated_process", "process_name",
    "grant_uri_permissions", "path_permission_count", "auto_verify",
    "exported_effective", "exported_effective_source", "android12_exported_violation",
]

PERMISSION_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "app_country_code", "app_region_group", "permission_id", "record_type",
    "permission_name", "permission_namespace", "family", "is_android_standard",
    "is_custom", "protection_level", "label_present", "description_present",
    "source_element", "source_xml", "is_privacy_sandbox_permission", "notes",
]

NETWORK_COLUMNS = [
    "run_id", "schema_version", "parser_version", "sample_id", "package_name",
    "app_country_code", "app_region_group", "network_rule_id", "config_file",
    "config_scope", "config_source", "rule_type", "domain", "include_subdomains",
    "cleartext_permitted", "trust_anchor_src", "pin_digest", "override_pins",
    "is_debug_override", "applies_when_debuggable",
]

# ═══════════════════════════════════════════════════════════════════════════════
# COLUMN TYPE SETS
# ═══════════════════════════════════════════════════════════════════════════════

BOOL_COLUMNS = {
    "uses_sdk_present", "debuggable", "extract_native_libs", "hardware_accelerated",
    "network_security_config_present", "has_manifest", "has_smali", "has_native_libs",
    "has_res_xml", "has_shared_user_id", "full_backup_content_present",
    "data_extraction_rules_present", "allow_backup_present", "allow_backup_value",
    "allow_backup_effective", "cleartext_global_explicit", "cleartext_global_default",
    "cleartext_global_effective_manifest", "cleartext_attr_ignored_on_target38_plus",
    "ps_topics", "ps_attribution", "ps_custom_audience", "ps_ad_id",
    "netcfg_main_cleartext_global", "netcfg_trust_user_certs_production",
    "netcfg_has_debug_overrides", "netcfg_main_config_found", "detected_manifest",
    "detected_smali", "detected_native", "detected_strings", "enabled_explicit_present",
    "enabled_explicit_value", "enabled_effective", "exported_explicit_present",
    "exported_explicit_value", "has_intent_filter", "is_launcher", "is_browsable",
    "has_permission_guard", "direct_boot_aware", "isolated_process",
    "grant_uri_permissions", "auto_verify", "exported_effective",
    "android12_exported_violation", "is_android_standard", "is_custom",
    "label_present", "description_present", "is_privacy_sandbox_permission",
    "include_subdomains", "cleartext_permitted", "override_pins", "is_debug_override",
    "applies_when_debuggable",
}

INT_COLUMNS = {
    "min_sdk", "target_sdk", "uses_libraries_count", "uses_feature_count",
    "uses_feature_required_count", "instrumentation_count", "activity_alias_count",
    "requested_permission_total", "requested_permission_unique",
    "requested_permission_dangerous_unique", "requested_permission_other_unique",
    "declared_permission_count", "declared_permission_group_count",
    "declared_permission_tree_count", "declared_signature_permission_count",
    "declared_normal_permission_count", "declared_custom_permission_count",
    "component_total", "activity_count", "service_count", "receiver_count",
    "provider_count", "exported_activities", "exported_services",
    "exported_receivers", "exported_providers", "exported_receivers_no_perm",
    "android12_exported_missing_count", "exported_components_with_intent_filter",
    "exported_components_with_custom_scheme", "deep_link_total",
    "deep_link_custom_scheme_count", "deep_link_https_count", "deep_link_http_count",
    "deep_link_market_count", "sdk_detected_count", "sdk_china_count",
    "sdk_usa_count", "sdk_india_count", "sdk_israel_count", "sdk_eu_count",
    "sdk_other_count", "netcfg_cleartext_exception_count",
    "netcfg_pinned_domain_count", "netcfg_additional_config_count",
    "secret_public_id_count", "secret_sensitive_token_count",
    "secret_possible_credential_count", "queries_package_count",
    "queries_intent_count", "queries_provider_count", "evidence_count",
    "occurrence_count", "source_file_count",
    "intent_filter_count", "action_count", "category_count", "data_count",
    "custom_scheme_count", "http_scheme_count", "https_scheme_count",
    "market_scheme_count", "other_scheme_count", "path_permission_count",
    *ALL_FAMILIES, *[f"sdk_{cat}_count" for cat in SDK_CATEGORIES],
}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _default_for_column(col: str):
    if col == "sdk_version_confidence":
        return "none"
    if col == "sdk_ecosystem":
        return "custom"
    if col == "finding_confidence":
        return "low"
    if col == "finding_metadata":
        return "{}"
    if col in BOOL_COLUMNS:
        return None
    if col in INT_COLUMNS:
        return 0
    return ""


def _normalize_rows(rows: List[Dict[str, Any]], columns: List[str]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        item = {}
        for col in columns:
            val = row.get(col, _default_for_column(col))
            item[col] = val
        out.append(item)
    return out
