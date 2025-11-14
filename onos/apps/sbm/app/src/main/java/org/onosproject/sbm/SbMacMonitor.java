/*
 * Southbound MAC Monitor Application
 * Listens to PacketIn events and stores MAC addresses from incoming traffic.
 */
package org.onosproject.sbm;

//import org.apache.felix.scr.annotations.*;
import org.osgi.service.component.annotations.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.packet.*;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.Objective;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component(
    immediate = true,
    service = SbMacMonitor.class
)
public class SbMacMonitor {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final SbPacketProcessor processor = new SbPacketProcessor();

    // Store learned MACs and their connection points
    private final ConcurrentHashMap<MacAddress, ConnectPoint> macTable = new ConcurrentHashMap<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.sbm");
        packetService.addProcessor(processor, PacketProcessor.director(2));

        // Request IPv4 and ARP packets from switches
        // IPv4 packets
        // TrafficSelector ipv4Selector = DefaultTrafficSelector.builder()
        //         .matchEthType(Ethernet.TYPE_IPV4)
        //         .build();
        // packetService.requestPackets(ipv4Selector, PacketPriority.REACTIVE, appId);

        // // ARP packets
        // TrafficSelector arpSelector = DefaultTrafficSelector.builder()
        //         .matchEthType(Ethernet.TYPE_ARP)
        //         .build();
        // packetService.requestPackets(arpSelector, PacketPriority.REACTIVE, appId);

        // check for all traffic
        TrafficSelector selector = DefaultTrafficSelector.builder().build(); 
        packetService.requestPackets(selector, PacketPriority.CONTROL, appId);

        log.info("Started {}", appId.name());
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        macTable.clear();
        log.info("Stopped {}", appId.name());
    }

    private class SbPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) return;

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) return;

            MacAddress srcMac = ethPkt.getSourceMAC();
            ConnectPoint receivedFrom = pkt.receivedFrom();

            // Learn and log new MACs
            if (!macTable.containsKey(srcMac)) {
                macTable.put(srcMac, receivedFrom);
                log.info("Learned MAC {} via switch {}", srcMac, receivedFrom);
            }
        }
    }

    // CLI-accessible method
    public void printMacTable(AbstractShellCommand shell) {
        macTable.forEach((mac, cp) -> shell.print("MAC: %s → %s", mac, cp));
    }

    // Helper methods
    private void print(String format, Object... args) {
        log.info(String.format(format, args));
    }

    public Map<MacAddress, ConnectPoint> getMacTable() {
        return macTable;
    }

    public void clearMacTable() {
        macTable.clear();
    }

}
