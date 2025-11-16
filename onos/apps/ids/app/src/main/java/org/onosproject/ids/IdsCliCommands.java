package org.onosproject.ids;

//import org.apache.felix.scr.annotations.*;
import org.osgi.service.component.annotations.*;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
//import org.onosproject.cli.Argument;

/**
 * ONOS CLI commands for IDS alerts.
 */
public final class IdsCliCommands {

    private IdsCliCommands() {}

     // Helper to format timestamps
    public static String fmt(long ts) {
        return Instant.ofEpochMilli(ts)
                .atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
    }

    // === 1. LIST DETECTIONS ===
    @Service
    @Command(scope = "onos", name = "ids-detections",
            description = "Lists all detected malicious flows")
    public static class IdsDetectionsCommand extends AbstractShellCommand {

        @Override
        protected void doExecute() {
            IdsMonitor m = get(IdsMonitor.class);

            print("=== IDS Detected Attacks ===");

            m.getAttackRecords().forEach((id, rec) -> {
                //print("ID=%d | type=%s | timestamp=%d", id.toString(), rec.label, fmt(rec.timestamp));
                print("ID=%s | type=%s | timestamp=%s", id.toString(), rec.label, fmt(rec.timestamp));
            });
        }
    }


    // === 2. ATTACK INFO ===
    @Service
    @Command(scope = "onos", name = "ids-attack-info",
            description = "Shows full information about a specific detected attack")
    public static class IdsAttackInfoCommand extends AbstractShellCommand {

        @Argument(index = 0, name = "id", description = "Attack ID", required = true)
        long id;

        @Override
        protected void doExecute() {
            IdsMonitor m = get(IdsMonitor.class);
            AttackRecord rec = m.getAttackRecord(id);

            if (rec == null) {
                print("No attack with ID %d found.", id);
                return;
            }

            print("=== Attack %d ===", rec.id);
            print("Timestamp: %s", fmt(rec.timestamp));
            print("Type: %s", rec.label);

            rec.flow.forEach((k, v) -> print("%s: %s", k, v));
        }
    }
}

