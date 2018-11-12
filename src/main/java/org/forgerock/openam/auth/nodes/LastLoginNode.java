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
 * Copyright 2017 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.*;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;
import java.util.*;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import org.forgerock.openam.utils.Time;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


/**
 * A node which stores a user's login history
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = LastLoginNode.Config.class)
public class LastLoginNode extends SingleOutcomeNode {

    private final static String DEBUG_FILE = "LastLoginNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private final CoreWrapper coreWrapper;

    public enum SaveStatus { SUCCESS, FAILURE }

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * A map of property name to value.
         * @return a map of properties.
         */
        @Attribute(order = 100)
        default String profileAttribute() {
            return "";
        }

        @Attribute(order = 200)
        default SaveStatus saveStatus() {
            return SaveStatus.SUCCESS;
        }


        @Attribute(order = 300)
        default boolean simple() {
            return false;
        }

        @Attribute(order = 400)
        default int savedLogins() {
            return 5;
        }

        @Attribute(order = 500)
        List<String> sharedState();
    }

    private final Config config;

    /**
     * Constructs a new LastLoginNode instance.
     * @param config Node configuration.
     */
    @Inject
    public LastLoginNode(@Assisted Config config, CoreWrapper coreWrapper) {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) {

        debug.message("[" + DEBUG_FILE + "]: " + "Starting");

        AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(), context.sharedState.get(REALM).asString());

        String resultString;

        String statusString = (config.saveStatus() == SaveStatus.SUCCESS) ? "SUCCESS" : "FAILED";

        if (config.simple()) {
            resultString = Time.newDate().toString() + " : " + statusString;
        } else {

            // get current last login attribute

            String lastLogin = "[]";
            try {

                Set<String> idAttrs = userIdentity.getAttribute(config.profileAttribute());
                if (idAttrs == null || idAttrs.isEmpty()) {
                    debug.error("[" + DEBUG_FILE + "]: " + "Unable to find attribute value for: " + config.profileAttribute());
                } else {
                    debug.error("[" + DEBUG_FILE + "]: " + "Found attribute value for: " + config.profileAttribute());
                    lastLogin = idAttrs.iterator().next();
                }
            } catch (IdRepoException e) {
                debug.error("[" + DEBUG_FILE + "]: " + " Error reading profile atttibute '{}' ", e);
            } catch (SSOException e) {
                debug.error("[" + DEBUG_FILE + "]: " + "Node exception", e);
            }


            // convert to JSON

            JSONArray jsonArray = new JSONArray();
            try {
                jsonArray = new JSONArray(lastLogin);
            } catch (JSONException e) {
                debug.error("[" + DEBUG_FILE + "]: " + "Unable to interpret JSON object. Creating new.");
            }


            // add new details - selected shared state values

            JSONObject newState = new JSONObject();
            for (String key : config.sharedState()) {
                if (context.sharedState.isDefined(key)) {
                    try {
                        if (context.sharedState.get(key).isString())
                            newState.put(key, context.sharedState.get(key).asString());
                        else
                            newState.put(key, context.sharedState.get(key));
                    } catch (JSONException e) {
                    }
                    ;
                }
            }


            String newEntry = "{ \"date\": \"" + Time.currentTimeMillis() + "\", \"status\": \"" + statusString + "\", \"sharedState\": " + newState.toString() + " }";
            JSONArray newJsonArray = new JSONArray();
            try {
                JSONObject newJson = new JSONObject(newEntry);
                newJsonArray.put(newJson);
            } catch (JSONException e) {
                debug.error("[" + DEBUG_FILE + "]: " + "Unable to create JSON object: " + e);
            }

            for (int i = 0; ((i < jsonArray.length()) && (i < config.savedLogins() - 1)); i++) {
                try {
                    newJsonArray.put(jsonArray.get(i));
                } catch (JSONException e) {
                }
                ;
            }

            resultString = newJsonArray.toString();
        }

        // store last login attribute

        Map<String, Set> map = new HashMap<String, Set>();
        Set<String> values = new HashSet<String>();
        values.add(resultString);
        map.put(config.profileAttribute(), values);
        try {
            userIdentity.setAttributes(map);
            userIdentity.store();
        } catch (IdRepoException e) {
            debug.error("[" + DEBUG_FILE + "]: " + " Error storing profile atttibute '{}' ", e);
        } catch (SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Node exception", e);
        }

        return goToNext().build();
    }
}
