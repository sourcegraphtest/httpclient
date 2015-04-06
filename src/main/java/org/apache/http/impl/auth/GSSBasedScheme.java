/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.http.impl.auth;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.annotation.NotThreadSafe;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.Args;
import org.apache.http.util.CharArrayBuffer;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

@NotThreadSafe
public class GSSBasedScheme extends AuthSchemeBase {

	private final Log logger = LogFactory.getLog(getClass());

    private static final String KERBEROS5_OID = "1.2.840.113554.1.2";
    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";

    private static final Map<String, String> schemesToMechOids = new HashMap<String, String>(2);

    static {
        schemesToMechOids.put(AuthSchemes.KERBEROS, KERBEROS5_OID);
        schemesToMechOids.put(AuthSchemes.SPNEGO, SPNEGO_OID);
    }

    enum State {
        NOT_STARTED, IN_PROGRESS, COMPLETED
    }

    private final String scheme;
    private final String mechOidStr;

    private State state;
    private byte[] inputToken;
    private GSSContext gssContext;

    public GSSBasedScheme(final String scheme) {
        Args.notBlank(scheme, "scheme");

        mechOidStr = schemesToMechOids.get(scheme);

        if (mechOidStr == null)
            throw new IllegalArgumentException(String.format(
                    "Scheme '%s' cannot be mapped to an OID", scheme));

        this.scheme = scheme;
        this.state = State.NOT_STARTED;
    }

    @Override
    public String getSchemeName() {
        return scheme;
    }

    @Override
    public String getParameter(final String name) {
        return null;
    }

    @Override
    public String getRealm() {
        return null;
    }

    @Override
    public boolean isConnectionBased() {
        return true;
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETED;
    }

    @Override
    @Deprecated
    public Header authenticate(final Credentials credentials, final HttpRequest request)
            throws AuthenticationException {
        return authenticate(credentials, request, new BasicHttpContext());
    }

    @Override
    public Header authenticate(final Credentials credentials, final HttpRequest request, final HttpContext context)
            throws AuthenticationException {
    	logger.debug("Performing SPNEGO authentication");
        switch (state) {
        case COMPLETED:
            // TODO implement me!
            state = State.NOT_STARTED;
        case NOT_STARTED:
            final GSSManager gssManager = GSSManager.getInstance();

            Oid mechOid;
            try {
                mechOid = new Oid(mechOidStr);

                final HttpRoute route = (HttpRoute) context
                        .getAttribute(HttpClientContext.HTTP_ROUTE);
                if (route == null) {
                    throw new AuthenticationException("Connection route is not available");
                }
                HttpHost host;
                if (isProxy()) {
                    host = route.getProxyHost();
                    if (host == null) {
                        host = route.getTargetHost();
                    }
                } else {
                    host = route.getTargetHost();
                }
                final String hostname = host.getHostName();

                final GSSName targetName = gssManager.createName("HTTP@" + hostname,
                        GSSName.NT_HOSTBASED_SERVICE, mechOid);

                gssContext = gssManager.createContext(targetName, mechOid, null,
                        GSSCredential.DEFAULT_LIFETIME);
                gssContext.requestCredDeleg(true);
                gssContext.requestMutualAuth(true);

                byte[] outputToken = gssContext.initSecContext(inputToken, 0, inputToken.length);
                inputToken = new byte[0];
                state = gssContext.isEstablished() ? State.COMPLETED : State.IN_PROGRESS;

                final String base64OutputToken = Base64.encodeBase64String(outputToken);
                outputToken = null;

                final StringBuilder buf = new StringBuilder(scheme);
                buf.append(' ');
                buf.append(base64OutputToken);

                final Header responseHeader = new BasicHeader(isProxy() ? AUTH.PROXY_AUTH_RESP
                        : AUTH.WWW_AUTH_RESP, buf.toString());

                if(state == State.COMPLETED) {
                    gssContext.dispose();
                    gssContext = null;
                }

                return responseHeader;

            } catch (GSSException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            break;
        case IN_PROGRESS:
            try {
                byte[] outputToken = gssContext.initSecContext(inputToken, 0, inputToken.length);
                inputToken = new byte[0];
                state = gssContext.isEstablished() ? State.COMPLETED : State.IN_PROGRESS;

                final String base64OutputToken = Base64.encodeBase64String(outputToken);
                outputToken = null;

                final StringBuilder buf = new StringBuilder(scheme);
                buf.append(' ');
                buf.append(base64OutputToken);

                final Header responseHeader = new BasicHeader(isProxy() ? AUTH.PROXY_AUTH_RESP
                        : AUTH.WWW_AUTH_RESP, buf.toString());

                if(state == State.COMPLETED) {
                    gssContext.dispose();
                    gssContext = null;
                }

                return responseHeader;
            } catch (GSSException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            break;

        }

        return null;
    }

    @Override
    protected void parseChallenge(final CharArrayBuffer buffer, final int beginIndex, final int endIndex)
            throws MalformedChallengeException {
        final String base64InputToken = buffer.substringTrimmed(beginIndex, endIndex);

        logger.debug("Received SPNEGO token: " + base64InputToken);

        inputToken = Base64.decodeBase64(base64InputToken);

        if (inputToken == null)
            inputToken = new byte[0];
    }

}
