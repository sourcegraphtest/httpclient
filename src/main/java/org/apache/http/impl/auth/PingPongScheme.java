/*
 * ==================================================================== Licensed to the Apache
 * Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in
 * writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 * ==================================================================== This software consists of
 * voluntary contributions made by many individuals on behalf of the Apache Software Foundation. For
 * more information on the Apache Software Foundation, please see <http://www.apache.org/>.
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
public class PingPongScheme extends AuthSchemeBase {

	private final Log logger = LogFactory.getLog(getClass());

	enum State {
		NOT_STARTED, IN_PROGRESS, COMPLETED
	}

	private State state;
	private String inputToken;
	private int loopCount;

	public PingPongScheme() {
		this.state = State.NOT_STARTED;
		this.loopCount = 0;
	}

	@Override
	public String getSchemeName() {
		return "PingPong";
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
	public Header authenticate(final Credentials credentials, final HttpRequest request,
			final HttpContext context) throws AuthenticationException {
		logger.debug("Using instance " + System.identityHashCode(this));
		switch (state) {
		case COMPLETED:
			// TODO implement me!
			state = State.NOT_STARTED;
			logger.debug("Resetting scheme state to from " + State.COMPLETED + " to "
					+ State.NOT_STARTED);
		case NOT_STARTED: {
			logger.debug("Starting PingPong authentication");

			state = State.IN_PROGRESS;

			loopCount++;

			final Header responseHeader = new BasicHeader(isProxy() ? AUTH.PROXY_AUTH_RESP
					: AUTH.WWW_AUTH_RESP, "PingPong " + loopCount);
			return responseHeader;
		}
		case IN_PROGRESS:
		{
			if(inputToken.equals("GameOver")) {
				state = State.COMPLETED;
				logger.debug("PingPong authentication completed");
			} else {
				int progressLoopCount;

				try {
					progressLoopCount = Integer.parseInt(inputToken);
				} catch(NumberFormatException e) {
					throw new AuthenticationException("Roundtrip failed: " + inputToken, e);
				}

				if(progressLoopCount != loopCount +1)
					throw new AuthenticationException(String.format("Roundtrip failed: %d != %d", progressLoopCount, loopCount+1));

				loopCount = progressLoopCount;
				loopCount++;

				final Header responseHeader = new BasicHeader(isProxy() ? AUTH.PROXY_AUTH_RESP
						: AUTH.WWW_AUTH_RESP, "PingPong " + loopCount);
				return responseHeader;
			}
		}

		}

		return null;
	}

	@Override
	protected void parseChallenge(final CharArrayBuffer buffer, final int beginIndex,
			final int endIndex) throws MalformedChallengeException {
		inputToken = buffer.substringTrimmed(beginIndex, endIndex);
	}

}
