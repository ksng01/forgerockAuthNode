/*
 * jon.knight@forgerock.com
 *
 * Gets user profile attributes
 *
 */
/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2019 ForgeRock AS.
 */
package org.forgerock.openam.auth.nodes;

import static org.forgerock.json.JsonValue.array;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;

/**
 * A node which contributes a configurable set of properties to be added to the user's session, if/when it is created.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = GetProfilePropertyNode.Config.class)
public class GetProfilePropertyNode extends SingleOutcomeNode {

    private static final Logger logger = LoggerFactory.getLogger(GetProfilePropertyNode.class);
    private final CoreWrapper coreWrapper;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * A map of property name to value.
         *
         * @return a map of properties.
         */
        @Attribute(order = 100)
        Map<String, String> properties();
    }

    private final Config config;

    /**
     * Constructs a new GetSessionPropertiesNode instance.
     *
     * @param config Node configuration.
     */
    @Inject
    public GetProfilePropertyNode(@Assisted Config config, CoreWrapper coreWrapper) {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) {
        String username = context.sharedState.get(USERNAME).asString();
        String realm = context.sharedState.get(REALM).asString();
        logger.trace("Searching for user {} in realm {}", username, realm);
        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);
        if (userIdentity == null) {
            logger.error("Unable to find user identity, profile attributes will not be saved in shared state");
            return goToNext().build();
        }

        JsonValue newSharedState = context.sharedState.copy();
        Set<String> attributesToRetrieve = config.properties().keySet();
        try {
            @SuppressWarnings("unchecked")
            Map<String, Set<String>> attributes = userIdentity.getAttributes(attributesToRetrieve);
            for (String attribute : attributesToRetrieve) {
                Set<String> values = attributes.get(attribute);
                if (values == null || values.isEmpty()) {
                    logger.warn("Unable to find attribute value for: {}", attribute);
                } else {
                    logger.trace("Found attribute value for: {}", attribute);
                    newSharedState.put(config.properties().get(attribute), convertValues(values));
                }
            }
        } catch (IdRepoException | SSOException ex) {
            logger.error("Unable to retrieve profile attributes", ex);
        }

        return goToNext().replaceSharedState(newSharedState).build();
    }

    private Object convertValues(Set<String> values) {
        if (values.size() == 1) {
            return values.iterator().next();
        } else {
            return array(values.toArray());
        }
    }
}
