/*
 * CLI command to display learned MAC addresses from the SBM app.
 */
package org.onosproject.sbm;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "sbm-macs",
        description = "Displays MAC addresses learned by the Southbound MAC Monitor")
public class SbMacCommand extends AbstractShellCommand {

    @Override
    protected void doExecute() {
        SbMacMonitor sbMacMonitor = AbstractShellCommand.get(SbMacMonitor.class);
        this.print("MAC addresses of incoming traffic:");
        sbMacMonitor.printMacTable(this);
    }
}
