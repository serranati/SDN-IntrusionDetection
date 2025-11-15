package org.onosproject.ids;

//import org.apache.felix.scr.annotations.*;
import org.osgi.service.component.annotations.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "ids-stats",
        description = "Displays the latest statistics regarding ML-based intrustion detection.")
public class IdsCliCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        IdsMonitor idsMonitor = AbstractShellCommand.get(IdsMonitor.class);
        this.print("=== IDS Predictions ===");

        idsMonitor.getLastPredictions().forEach((flow, result) -> {
            this.print("%s -> %s", flow, result);
        });
    }
}
