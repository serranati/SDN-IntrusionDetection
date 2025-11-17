package org.onosproject.ids;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.osgi.service.component.annotations.*;
import org.onlab.util.Tools;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.device.DeviceService;
import org.onosproject.net.Device;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

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

    // Unique ID generator for attack alerts
    private final AtomicLong attackIdGen = new AtomicLong(1);

    // Store attack records: ID → AttackRecord
    private final ConcurrentHashMap<Long, AttackRecord> attackRecords = new ConcurrentHashMap<>();
    
    // make sure not to assign two different attack ids to the same flow 
    private final ConcurrentHashMap<Long, Boolean> alertedFlows = new ConcurrentHashMap<>();

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
     * Make the attack records available to the CLI
     */
    public Map<Long, AttackRecord> getAttackRecords() {
        return Collections.unmodifiableMap(attackRecords);
    }

    public AttackRecord getAttackRecord(long id) {
        return attackRecords.get(id);
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
                    //log.info("JSON data that is sent: {}", json.toString());
                    //log.info("Criteria for flow {}: {}", fe.id().value(), fe.selector().criteria());

                    if (json.get("src_ip") != null || json.get("eth_src") != null){
                        log.info("JSON data that is sent: {}", json.toString());
                    }

                    long flowRuleId = fe.id().value();

                    // Send request
                    String label = sendToIds(json);

                    if (label == null) continue;

                    if (!label.equalsIgnoreCase("normal")) {
                            if(!alertedFlows.containsKey(flowRuleId)) {
                            long id = attackIdGen.getAndIncrement();
                            AttackRecord rec = new AttackRecord(id, System.currentTimeMillis(), label, json);
                            attackRecords.put(id, rec);
                            alertedFlows.put(flowRuleId, true); // Mark this flow as alerted
                            log.warn("IDS ALERT [{}] => {}", id, json);
                        }
                        else {
                            // Flow is still malicious, but we skip creating a new alert to avoid duplication
                            log.info("Flow ID {} remains malicious. Skipping new alert creation.", flowRuleId);
                        }
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

        // Core flow stats
        long packets = fe.packets();
        long bytes   = fe.bytes();
        double dur   = fe.life() > 0 ? fe.life() : 1.0;

        m.put("flow_id", fe.id().value());
        m.put("device_id", device.id().toString());
        m.put("packet_count", packets);
        m.put("byte_count", bytes);
        m.put("duration_sec", dur);
        m.put("packets_per_sec", (Double) packets / dur);
        m.put("bytes_per_sec", (Double) bytes / dur);
        m.put("last_seen", IdsCliCommands.fmt(fe.lastSeen()));

        // Defaults
        m.put("src_ip", null);
        m.put("dst_ip", null);
        m.put("src_port", null);
        m.put("dst_port", null);
        m.put("protocol", null);
        m.put("eth_src", null);
        m.put("eth_dst", null);
        m.put("in_port", null);

        // Extract criteria
        for (Criterion c : fe.selector().criteria()) {
            switch (c.type()) {
                case ETH_SRC:
                    m.put("eth_src", ((EthCriterion) c).mac().toString());
                    break;

                case ETH_DST:
                    m.put("eth_dst", ((EthCriterion) c).mac().toString());
                    break;

                case IN_PORT:
                    m.put("in_port", ((PortCriterion) c).port().toLong());
                    break;

                case IPV4_SRC:
                    m.put("src_ip", ((IPCriterion) c).ip().address().toString());
                    break;

                case IPV4_DST:
                    m.put("dst_ip", ((IPCriterion) c).ip().address().toString());
                    break;

                case TCP_SRC:
                    m.put("src_port", ((TcpPortCriterion) c).tcpPort().toInt());
                    break;

                case TCP_DST:
                    m.put("dst_port", ((TcpPortCriterion) c).tcpPort().toInt());
                    break;

                case UDP_SRC:
                    m.put("src_port", ((UdpPortCriterion) c).udpPort().toInt());
                    break;

                case UDP_DST:
                    m.put("dst_port", ((UdpPortCriterion) c).udpPort().toInt());
                    break;

                case IP_PROTO:
                    m.put("protocol", ((IPProtocolCriterion) c).protocol());
                    break;

                default:
                    break;
            }
        }

        return m;
    }


    /**
     * Sends flow JSON to external IDS server.
     */
    private String sendToIds(Map<String, Object> json) {
        try {
            String jsonStr = mapper.writeValueAsString(json);
            //log.info("Actual JSON string: {}", jsonStr);

            byte[] postData = jsonStr.getBytes("UTF-8");

            URL url = new URL(IDS_API_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            // Send JSON
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int status = conn.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                log.warn("IDS server returned HTTP {}", status);
                return null;
            }

            // Read response
            StringBuilder response = new StringBuilder();
            try (InputStream is = conn.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is))) {

                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
            }

            // Parse JSON
            Map result = mapper.readValue(response.toString(), Map.class);
            return (String) result.get("label");

        } catch (Exception e) {
            log.warn("Error sending to IDS API: {}", e.getMessage());
            return null;
        }
    }


    /**
     * Exposed to the CLI: returns last predictions.
     */
    // public Map<String, String> getLastPredictions() {
    //     return lastPredictions;
    // }
}
