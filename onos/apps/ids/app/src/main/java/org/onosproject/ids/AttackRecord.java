package org.onosproject.ids;

import java.util.Map;

public class AttackRecord {
    public final long id;
    public final long timestamp;
    public final String label;
    public final Map<String, Object> flow;

    public AttackRecord(long id, long timestamp, String label, Map<String, Object> flow) {
        this.id = id;
        this.timestamp = timestamp;
        this.label = label;
        this.flow = flow;
    }
}
