package com.cybershield.app.engine;

import java.util.ArrayList;
import java.util.List;

/** Result of the on-device pre-check. Mirrors the important fields of the server verdict. */
public class LocalVerdict {

    public enum Level { SAFE, SUSPICIOUS, HIGH_RISK, MALICIOUS }

    public int score;
    public Level level = Level.SAFE;
    public final List<String> reasons = new ArrayList<>();
    public boolean initiatesPayment;
    public boolean fromLocalOnly = true;   // true until a server verdict replaces it

    public void add(String reason, int weight) {
        reasons.add(reason);
        score = Math.min(100, score + weight);
    }

    public void finish() {
        if (score >= 75) level = Level.MALICIOUS;
        else if (score >= 50) level = Level.HIGH_RISK;
        else if (score >= 25) level = Level.SUSPICIOUS;
        else level = Level.SAFE;
    }

    public boolean isBlocking() {
        return level == Level.MALICIOUS || level == Level.HIGH_RISK;
    }

    public String priority() {
        switch (level) {
            case MALICIOUS: return "P1";
            case HIGH_RISK: return "P2";
            case SUSPICIOUS: return "P3";
            default: return "P4";
        }
    }
}
