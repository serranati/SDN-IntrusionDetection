package org.onosproject.ids;

import com.fasterxml.jackson.databind.ObjectMapper;
//import org.apache.felix.scr.annotations.*;
import org.osgi.service.component.annotations.*;
import org.onlab.util.Tools;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.device.DeviceService;
import org.onosproject.net.Device;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.*;
import java.util.concurrent.*;

/**
 * IDS application that periodically fetches ONOS flow statistics
 * and sends them to an external REST API for classification.
 */
@Component(immediate = true, service = IdsMonitor.class)
public class IdsMonitor {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference
    private CoreService coreService;

    @Reference
    private DeviceService deviceService;

    @Reference
    private FlowRuleService flowRuleService;

    private ApplicationId appId;
    private ScheduledExecutorService scheduler;

    private static final int PERIOD_SECONDS = 10;
    private static final String IDS_API_URL = "http://localhost:5000/predict";

    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, String> lastPredictions = new ConcurrentHashMap<>();

    private Client client;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.onosproject.ids");

        log.info("Starting IDS monitor (appId={})", appId);

        scheduler = Executors.newSingleThreadScheduledExecutor();
        client = ClientBuilder.newClient();

        scheduler.scheduleAtFixedRate(this::pollFlowsAndSend, 2, PERIOD_SECONDS, TimeUnit.SECONDS);

        log.info("IDS Monitor started");
    }

    @Deactivate
    protected void deactivate() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        if (client != null) {
            client.close();
        }
        log.info("Stopped IDS Monitor");
    }

    /**
     * Polls all flow entries and sends each to the IDS server.
     */
    private void pollFlowsAndSend() {
        try {
            for (Device device : deviceService.getDevices()) {
                Iterable<FlowEntry> flows = flowRuleService.getFlowEntries(device.id());

                for (FlowEntry fe : flows) {
                    Map<String, Object> json = buildFlowJson(device, fe);

                    // Send request
                    String prediction = sendToIds(json);

                    if (prediction != null) {
                        String key = device.id().toString() + ":" + fe.id().value();
                        lastPredictions.put(key, prediction);
                        log.info("IDS result for {} -> {}", key, prediction);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error polling flows: {}", e.getMessage());
        }
    }

    /**
     * Convert ONOS FlowEntry to JSON map compatible with your IDS API.
     */
    private Map<String, Object> buildFlowJson(Device device, FlowEntry fe) {
        Map<String, Object> m = new HashMap<>();

        m.put("device_id", device.id().toString());
        m.put("flow_id", fe.id().value());
        m.put("packet_count", fe.packets());
        m.put("byte_count", fe.bytes());
        m.put("duration_sec", fe.life());
        m.put("last_seen", fe.lastSeen());

        // Extract basic match fields
        fe.selector().criteria().forEach(c -> {
            m.put(c.type().name().toLowerCase(), c.toString());
        });

        return m;
    }

    /**
     * Sends flow JSON to external IDS server.
     */
    private String sendToIds(Map<String, Object> json) {
        try {
            String jsonStr = mapper.writeValueAsString(json);

            WebTarget target = client.target(IDS_API_URL);
            Response response = target.request(MediaType.APPLICATION_JSON)
                    .post(Entity.json(jsonStr));

            if (response.getStatus() != 200) {
                log.warn("IDS server returned status {}", response.getStatus());
                return null;
            }

            Map result = response.readEntity(Map.class);
            return (String) result.get("label");

        } catch (Exception e) {
            log.warn("Error sending to IDS API: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Exposed to the CLI: returns last predictions.
     */
    public Map<String, String> getLastPredictions() {
        return lastPredictions;
    }
}
