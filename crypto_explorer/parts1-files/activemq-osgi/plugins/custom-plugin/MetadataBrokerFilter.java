/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.example.activemq.custom.plugin;

import java.security.MessageDigest;

import javax.xml.bind.DatatypeConverter;

import org.apache.activemq.advisory.AdvisorySupport;
import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerFilter;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.broker.region.Destination;
import org.apache.activemq.command.ActiveMQDestination;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MetadataBrokerFilter extends BrokerFilter {
	private static final Logger LOGGER = LoggerFactory.getLogger(MetadataBrokerFilter.class);

	MetadataBrokerPlugin plugin;
	
    public MetadataBrokerFilter(Broker next, MetadataBrokerPlugin plugin) {
	    super(next);
	    this.plugin = plugin;
	}

    @Override
    public Destination addDestination(ConnectionContext context, ActiveMQDestination destination, boolean createIfTemporary) throws Exception {
        String dn = destination.getPhysicalName();
    	if (!AdvisorySupport.isAdvisoryTopic(destination)) {
            // This fictitious plugin sends metadata about new destinations to a 'store'
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dn.getBytes("UTF-8"));
            LOGGER.info("Storing metadata: '{}' for destination '{}'.", DatatypeConverter.printBase64Binary(hash), dn);
        }
        LOGGER.debug("Adding destination: '{}'.", dn);
        return super.addDestination(context, destination, createIfTemporary);
    }

    @Override
    public void removeDestination(ConnectionContext context, ActiveMQDestination destination, long timeout) throws Exception {
        LOGGER.debug("Removing destination: '{}'.", destination.getPhysicalName());
        super.removeDestination(context, destination, timeout);
    }

}

