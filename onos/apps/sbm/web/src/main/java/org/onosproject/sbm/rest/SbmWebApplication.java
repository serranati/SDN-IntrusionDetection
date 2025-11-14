package org.onosproject.sbm.rest;

import java.util.Set;

import org.onlab.rest.AbstractWebApplication;

public class SbmWebApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(SbmWebResource.class);
    }
}
