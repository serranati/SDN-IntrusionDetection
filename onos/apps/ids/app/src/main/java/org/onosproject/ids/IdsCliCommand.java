package org.onosproject.ids;

//import org.apache.felix.scr.annotations.*;
import org.osgi.service.component.annotations.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "sbm-macs",
        description = "Displays MAC addresses learned by the Southbound MAC Monitor")
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
