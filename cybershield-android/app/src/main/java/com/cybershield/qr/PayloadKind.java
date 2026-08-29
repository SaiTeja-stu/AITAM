package com.cybershield.qr;

/** Classification of a decoded QR payload (spec: "Determine whether it contains..."). */
public enum PayloadKind {
    UPI_PAYMENT,
    URL,
    PLAIN_TEXT,
    WIFI,
    CONTACT,
    SMS_INTENT,
    TEL,
    EMAIL,
    GEO,
    OTHER
}
