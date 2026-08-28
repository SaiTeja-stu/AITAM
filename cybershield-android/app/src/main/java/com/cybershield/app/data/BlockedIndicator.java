package com.cybershield.app.data;

import androidx.annotation.NonNull;
import androidx.room.Entity;

/**
 * On-device blocklist entry, synced from the backend. Domains stored in the
 * clear; VPAs and phone numbers stored ONLY as HMAC hashes (the backend serves
 * them pre-hashed) so the device never holds a list of real payment IDs.
 */
@Entity(tableName = "blocked", primaryKeys = {"type", "value"})
public class BlockedIndicator {

    public static final String TYPE_DOMAIN = "DOMAIN";
    public static final String TYPE_VPA = "VPA_HASH";
    public static final String TYPE_PHONE = "PHONE_HASH";

    @NonNull public String type = TYPE_DOMAIN;
    @NonNull public String value = "";
    public long syncedAt;
}
