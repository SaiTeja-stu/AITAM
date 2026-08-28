package com.cybershield.app.data;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

/** Local history row. Stores only a short redacted snippet, never full content. */
@Entity(tableName = "scan")
public class ScanEntity {

    @PrimaryKey
    @NonNull
    public String id = "";

    public String type;          // URL / SMS / QR ...
    public String snippet;       // redacted, <= 200 chars
    public int riskScore;
    public String riskLevel;     // SAFE / SUSPICIOUS / HIGH_RISK / MALICIOUS
    public String priority;      // P1..P4
    public boolean serverChecked;
    public long createdAt;
}
