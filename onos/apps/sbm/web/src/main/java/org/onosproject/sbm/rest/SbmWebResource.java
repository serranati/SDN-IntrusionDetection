package org.onosproject.sbm.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onosproject.rest.AbstractWebResource;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.host.HostService;
import org.onlab.packet.MacAddress;
import org.onosproject.sbm.SbMacMonitor;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Path("")
public class SbmWebResource extends AbstractWebResource {
    private final ObjectMapper mapper = new ObjectMapper();

    @GET
    @Path("macs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMacs() {
        SbMacMonitor monitor = get(SbMacMonitor.class);
        Map<MacAddress, ConnectPoint> macTable = monitor.getMacTable();

        ObjectNode root = mapper.createObjectNode();

        macTable.forEach((mac, cp) -> root.put(mac.toString(), cp.toString()));

        return ok(root).build();
    }

    @GET
    @Path("macs/{mac}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMac(@PathParam("mac") String mac) {
        SbMacMonitor monitor = get(SbMacMonitor.class);
        ConnectPoint cp = monitor.getMacTable().get(MacAddress.valueOf(mac));
        if (cp != null) {
            return Response.ok(cp.toString()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("MAC not found").build();
        }
    }

    @GET
    @Path("ip/{ip}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMacByIp(@PathParam("ip") String ip) {
        SbMacMonitor monitor = get(SbMacMonitor.class);

        // Look through hosts to match the IP
        return monitor.getMacTable().entrySet().stream()
                .filter(entry -> {
                    // get the host(s) at this MAC
                    return get(HostService.class).getHostsByMac(entry.getKey())
                            .stream()
                            .anyMatch(host -> host.ipAddresses().stream()
                                    .anyMatch(hostIp -> hostIp.toString().equals(ip)));
                })
                .findFirst()
                .map(entry -> {
                    ObjectNode root = mapper.createObjectNode();
                    root.put(ip, entry.getKey().toString());
                    return ok(root).build();
                })
                .orElse(Response.status(Response.Status.NOT_FOUND)
                        .entity("IP not found").build());
    }


    @DELETE
    @Path("macs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response clearMacs() {
        SbMacMonitor monitor = get(SbMacMonitor.class);
        monitor.clearMacTable();
        return Response.ok("MAC table cleared").build();
    }
}
