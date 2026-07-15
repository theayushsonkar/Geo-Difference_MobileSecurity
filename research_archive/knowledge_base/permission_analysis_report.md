# Permission Analysis Report

- **Total unique permissions:** 396
- **Mapped permissions:** 8
- **Unknown permissions:** 388
- **Coverage percentage:** 2.02%

## Top 50 Most Common Unknown Permissions
| Permission | API Count |
|---|---|
| android.permission.INTERACT_ACROSS_USERS_FULL | 297 |
| android.permission.BLUETOOTH | 193 |
| android.permission.CONNECTIVITY_INTERNAL | 153 |
| android.permission.MODIFY_PHONE_STATE | 132 |
| android.permission.READ_PRIVILEGED_PHONE_STATE | 101 |
| android.permission.UPDATE_DEVICE_STATS | 94 |
| ti.permission.FMRX_ADMIN | 94 |
| android.permission.BACKUP | 74 |
| android.permission.BLUETOOTH_ADMIN | 73 |
| android.permission.CHANGE_WIFI_STATE | 52 |
| android.permission.ACCESS_WIFI_STATE | 50 |
| android.permission.BLUETOOTH, android.permission.BLUETOOTH_ADMIN | 46 |
| android.permission.WRITE_SECURE_SETTINGS | 40 |
| android.permission.NFC | 36 |
| android.permission.INTERACT_ACROSS_USERS | 36 |
| android.permission.DEVICE_POWER | 35 |
| android.permission.STATUS_BAR_SERVICE | 34 |
| android.permission.HDMI_CEC | 33 |
| android.permission.BIND_APPWIDGET | 25 |
| android.permission.MANAGE_APP_TOKENS | 25 |
| android.permission.STATUS_BAR | 23 |
| android.permission.MANAGE_ACTIVITY_STACKS | 23 |
| android.permission.BROADCAST_STICKY, android.permission.START_ANY_ACTIVITY | 21 |
| android.permission.MANAGE_NETWORK_POLICY | 20 |
| android.permission.ACCESS_KEYGUARD_SECURE_STORAGE | 20 |
| android.permission.ACCESS_COARSE_LOCATION, android.permission.ACCESS_FINE_LOCATION | 19 |
| android.permission.MOUNT_UNMOUNT_FILESYSTEMS | 17 |
| android.permission.BLUETOOTH_PRIVILEGED | 17 |
| android.permission.AUTHENTICATE_ACCOUNTS | 16 |
| android.permission.BROADCAST_STICKY | 16 |
| android.permission.MANAGE_USB | 16 |
| android.permission.CONFIGURE_WIFI_DISPLAY | 15 |
| android.permission.LOCATION_HARDWARE | 15 |
| android.permission.BROADCAST_STICKY, android.permission.MANAGE_ACTIVITY_STACKS | 15 |
| android.permission.BIND_DEVICE_ADMIN, android.permission.INTERACT_ACROSS_USERS_FULL | 14 |
| android.permission.STORAGE_INTERNAL | 14 |
| android.permission.MANAGE_ACCOUNTS | 13 |
| android.permission.MODIFY_AUDIO_SETTINGS | 13 |
| android.permission.ACCESS_NETWORK_STATE, android.permission.CONNECTIVITY_INTERNAL | 13 |
| android.permission.RECEIVE_SMS, android.permission.SEND_SMS | 12 |
| android.permission.WAKE_LOCK | 12 |
| android.permission.SET_DEBUG_APP | 12 |
| android.permission.INTERACT_ACROSS_USERS, android.permission.INTERACT_ACROSS_USERS_FULL | 11 |
| android.permission.INTERACT_ACROSS_USERS_FULL, android.permission.MANAGE_USERS | 11 |
| android.permission.ACCOUNT_MANAGER | 10 |
| android.permission.WRITE_SYNC_SETTINGS | 10 |
| android.permission.SET_ACTIVITY_WATCHER | 10 |
| android.permission.INTERACT_ACROSS_USERS_FULL, android.permission.WRITE_SECURE_SETTINGS | 10 |
| android.permission.INTERACT_ACROSS_USERS_FULL, android.permission.SEND_RESPOND_VIA_MESSAGE, android.permission.SEND_SMS, android.permission.UPDATE_APP_OPS_STATS | 10 |
| android.permission.EXPAND_STATUS_BAR | 9 |

## Top Categories by API Count
| Category | Permission Count | API Count |
|---|---|---|
| Unknown | 396 | 3099 |

## Recommendations for Expanding `privacy_categories.csv`
1. Review `permission_mapping_review.csv` and verify the suggested mappings.
2. Add high-confidence suggestions directly to `metadata/privacy_categories.csv`.
3. Investigate the top unknown permissions to understand their privacy implications.
4. Create new categories if necessary for permissions that do not fit into existing ones (e.g., Settings, Connectivity).