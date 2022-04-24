/*
Copyright 2012 Johns Hopkins University Institute for Computational Medicine
Copyright 2012 University of Chicago

Based upon the GlobusOnline Nexus Client written in Python by Mattias Lidman  
available at https://github.com/globusonline/python-nexus-client

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
* @author Chris Jurado
* @author Josh Bryan
* 
*/

package org.globusonline.nexus;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.log4j.Logger;
import org.globusonline.nexus.exception.InvalidCredentialsException;
import org.globusonline.nexus.exception.InvalidUrlException;
import org.globusonline.nexus.exception.NexusClientException;
import org.globusonline.nexus.exception.ValueErrorException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class BaseNexusRestClient {

	protected String community = "go";
	private JSONObject currentUser;

	protected String nexusApiHost = "nexus.api.globusonline.org";

	boolean ignoreCertErrors = false;
	HostnameVerifier allHostsValid = new HostnameVerifier() {
		@Override
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};
	private NexusAuthenticator authenticator;
	protected static org.apache.log4j.Logger logger = Logger
			.getLogger(GlobusOnlineRestClient.class);
	
	static TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
		public void checkClientTrusted(X509Certificate[] certs, String authType) {
			return;
		}

		public void checkServerTrusted(X509Certificate[] certs, String authType) {
			return;
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	} };
	
	public BaseNexusRestClient() {
		super();
	}

	public JSONObject acceptInvitation(UUID gid, String username,
			String statusReason) throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "pending", "invited",
				"Only invited users can accept an invitation.", "");
	}
	
	public JSONObject approveJoin(UUID gid, String username, String statusReason)
			throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "active", "pending",
				"Only invited users can accept an invitation.", "");
	}

	public JSONObject buildPolicyDictionary(JSONObject kwargs) {
		// # Each kwargs must be a dictionary named after a policy, containing
		// policy
		// # options and values. For example:
		// # approval = { 'admin': True, 'auto_if_admin': False, 'auto': False,
		// }
		// # go_rest_client_tests.py contains an example setting all policies
		// available
		// # as of this writing.

		JSONObject policies = new JSONObject();

		Iterator<?> keys = kwargs.keys();

		while (keys.hasNext()) {

			try {
				String policy = (String) keys.next();
				JSONObject policyOptions = new JSONObject();
				JSONObject policyOptionsSource = new JSONObject();
				policyOptionsSource = kwargs.getJSONObject(policy);
				policyOptionsSource = kwargs.getJSONObject(policy);

				Iterator<?> subKeys = policyOptionsSource.keys();
				while (subKeys.hasNext()) {

					String optionKey = (String) subKeys.next();
					JSONObject newOption = new JSONObject();

					newOption.put("value", policyOptionsSource.get(optionKey));
					policyOptions.put(optionKey, newOption);
				}

				JSONObject jsonPolicy = new JSONObject();
				jsonPolicy.put("value", policyOptions);
				policies.put(policy, jsonPolicy);

			} catch (JSONException e) {
				logger.error("JSON Exception.");
				e.printStackTrace();
			}

		}

		return policies;
	}

	public JSONObject claimInvitation(String inviteId)
			throws NexusClientException {

		// # claim_invitation ties an email invite to a GO user, and must be
		// done
		// # before the invite can be accepted.

		String url = "/memberships/" + inviteId;
		JSONObject params = new JSONObject();
		Date date = new Date();
		Timestamp time = new Timestamp(date.getTime());

		try {

			JSONObject user = getCurrentUser();
			JSONObject membership = issueRestRequest(url);
			membership.put("username", (String) user.get("username"));
			membership.put("email", (String) user.get("email"));
			params.put("username", (String) user.get("username"));
			params.put("status", (String) membership.get("status"));
			params.put("status_reason",
					(String) membership.get("status_reason"));
			params.put("role", (String) membership.get("role"));
			params.put("email", (String) membership.get("email"));
			params.put("last_changed", time);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
			return null;
		}

		return issueRestRequest(url, "PUT", "", "", params);
	}

	public String getCommunity() {
		return community;
	}

	/**
	 * @return the currentUser
	 * @throws NexusClientException 
	 */
	public JSONObject getCurrentUser() throws NexusClientException {
		return currentUser;
	}

	public JSONObject getGroupEmailTemplate(UUID gid, UUID templateId) throws NexusClientException {
		// # Get a single email template, including message. The template_id can
		// # be gotten by using get_group_email_templates.
		String url = "/groups/" + gid + "/email_templates/" + templateId;
		return issueRestRequest(url);
	}

	public JSONObject getGroupEmailTemplates(UUID gid) throws NexusClientException {
		// # Returned document does not include the message of each template.
		// # Use get_group_email_template for that.
		String url = "/groups/" + gid + "/email_templates";
		return issueRestRequest(url);
	}

	public JSONObject getGroupList(String depth) throws NexusClientException {

		return getGroupList(null, depth);
	}

	public JSONObject getGroupList(UUID rootId, String depth)
			throws NexusClientException {

		String url = "";

		if (depth.equals("")) {
			depth = "1";
		}

		url = "/groups/list?depth=" + depth;

		if (rootId != null) {
			url = url + "&root=" + rootId;
		}

		return issueRestRequest(url);
	}

	public JSONObject getGroupMember(UUID gid, String username) throws NexusClientException {
		String url = "/groups/" + gid + "/members/" + username;
		return issueRestRequest(url);
	}

	public JSONObject getGroupMembers(UUID gid) throws NexusClientException {
		String url = "/groups/" + gid + "/members";
		return issueRestRequest(url);
	}

	public JSONObject getGroupPolicies(UUID gid) throws NexusClientException {
		String url = "/groups/" + gid + "/policies";
		return issueRestRequest(url);
	}

	public JSONObject getGroupSummary(UUID gid) throws NexusClientException {
		String url = "/groups/" + gid;
		return issueRestRequest(url);
	}

	public String getNexusApiHost() {
		return this.nexusApiHost;
	}

	public String getNexusApiUrl() {
		return "https://" + nexusApiHost;
	}

	public JSONObject getRenderedGroupEmailTemplate(UUID gid, UUID templateId)
			throws NexusClientException {
		String url = "/groups/" + gid + "/email_templates/" + templateId;
		JSONObject params = new JSONObject();

		try {
			params.put("mode", "view");
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return issueRestRequest(url, "", "", "", params);
	}

	public JSONObject getUser(String username) throws NexusClientException {

		return getUser(username, null, null);

	}

	public JSONObject getUser(String username, JSONArray fields,
			JSONArray customFields) throws NexusClientException {
		// # If no fields are explicitly set the following will be returned by
		// Graph:
		// # ['fullname', 'email', 'username', 'email_validated',
		// 'system_admin', 'opt_in']
		// # No custom fields are returned by default.
		String url = "";
		boolean includeParams = false;
		JSONObject queryParams = new JSONObject();

		try {

			if (fields != null) {
				queryParams.put("fields", queryParams);
				includeParams = true;
			}
			if (customFields != null) {
				queryParams.put("custom_fields", customFields);
				includeParams = true;
			}

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
			return null;
		}

		url = "/users/" + username;

		if (includeParams) {
			url = url + '?' + urlEncode(queryParams);
		}

		return issueRestRequest(url, "", "", "", null);
	}

	public JSONObject getUserPolicies(String username) throws NexusClientException {
		String url = "/users/" + username + "/policies";
		return issueRestRequest(url);
	}

	public JSONObject getUserSecret(String username) throws NexusClientException {
		// # Gets the secret used for OAuth authentication.
		JSONArray fieldsArray = new JSONArray();

		return getUser(username, fieldsArray, null);
	}

	public boolean isIgnoreCertErrors() {
		return ignoreCertErrors;
	}

	public JSONObject postEmailValidation(String validationCode) throws NexusClientException {
		String url = "/validation";
		JSONObject params = new JSONObject();
		try {
			params.put("validation_code", validationCode);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return issueRestRequest(url, "POST", "", "", params);
	}

	public JSONObject postGroup(String name, String description, UUID parent)
			throws NexusClientException {
		return postGroup(name, description, parent, true);
	}

	public JSONObject postGroup(String name, String description, UUID parentId,
			boolean isActive) throws NexusClientException {
		// # Create a new group.
		if (description.isEmpty()) {
			description = "A group called \"" + name + "\"";
		}

		JSONObject params = new JSONObject();
		try {
			params.put("name", name);
			params.put("description", description);
			params.put("is_active", isActive);

			if (parentId != null) {
				params.put("parent", parentId);
			}
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		String url = "/groups/";

		return issueRestRequest(url, "POST", "", "", params);
	}

	public JSONObject postGroupEmailTemplates(String gid, JSONObject params)
			throws NexusClientException {
		// # Create one or more new email templates.
		String url = "/groups/" + gid + "/email_templates";
		return issueRestRequest(url, "POST", "", "", params);
	}

	public JSONObject postMembership(String gid, JSONArray usernames,
			JSONArray emails) throws NexusClientException {
		// # POSTing a membership corresponds to inviting a user identified by a
		// # username or an email address to a group, or requesting to join a
		// group
		// # (if the actor is among the listed usernames).

		String url = "/groups/" + gid + "/members";

		JSONObject params = new JSONObject();
		try {
			params.put("users", usernames);
			params.put("emails", emails);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return issueRestRequest(url, "POST", "", "", params);
	}

	public JSONObject postMembership(String gid, String username, String email)
			throws NexusClientException {

		JSONArray usernames = new JSONArray();
		JSONArray emails = new JSONArray();

		usernames.put(username);
		emails.put(email);

		return postMembership(gid, usernames, emails);
	}

	public JSONObject postUser(String username, String fullname, String email,
			String password, JSONObject kwargs) throws NexusClientException {
		// # Create a new user.
		String acceptTerms = "True";
		String optIn = "True";
		JSONObject params = new JSONObject();

		try {

			if (kwargs.has("accept_terms")) {
				acceptTerms = (String) kwargs.get("accept_terms");
			}
			if (kwargs.has("opt_in")) {
				optIn = (String) kwargs.get("opt_in");
			}

			params.put("username", username);
			params.put("fullname", fullname);
			params.put("email", email);
			params.put("password", password);
			params.put("accept_terms", acceptTerms);
			params.put("optIn", optIn);

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
			return null;
		}

		return issueRestRequest("/users", "POST", "", "", params);
	}

	public JSONObject putGroupEmailTemplate(String gid, String templateId,
			JSONObject params) throws NexusClientException {
		// # Update an email template.
		String url = "/groups/" + gid + "/email_templates" + templateId;
		return issueRestRequest(url, "PUT", "", "", params);
	}

	public JSONObject putGroupMembership(String gid, String username,
			String email, String role, String status, String statusReason,
			String lastChanged, String userDetails) throws NexusClientException {
		// # PUT is used for accepting invitations and making other changes to a
		// membership.
		// # The document is validated against the following schema:
		// #
		// https://raw.github.com/globusonline/goschemas/integration/member.json
		// # membership_id == invite_id for purposes of accepting an invitation.

		String url = "/groups/" + gid + "/members" + username;
		return putGroupMembership(url, username, email, role, status,
				statusReason, userDetails);
	}

	public JSONObject putGroupMembershipById(String inviteId, String username,
			String email, String role, String status, String statusReason,
			String lastChanged, String userDetails) throws NexusClientException {
		// # put_group_membership_by_id() is used for tying an email invite to a
		// GO user,
		// # use put_group_membership() otherwise.

		String url = "/memberships/" + inviteId;
		return putGroupMembership(url, username, email, role, status,
				statusReason, userDetails);
	}

	public JSONObject putGroupMembershipRole(UUID gid, String username,
			String newRole) throws NexusClientException {

		JSONObject member = getGroupMember(gid, username);
		try {
			member.put("role", newRole);

			return putGroupMembership(gid.toString(), username,
					(String) member.get("email"), (String) member.get("role"),
					(String) member.get("status"),
					(String) member.get("statusReason"), null, null);

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
			return null;
		}

	}

	public JSONObject putGroupPolicies(UUID gid, JSONObject policies)
			throws NexusClientException {
		// # PUT policies in dict policies. Utility function
		// build_policy_dictionary()
		// # may be used to simplify building the document.
		String url = "/groups/" + gid + "/policies";

		return issueRestRequest(url, "PUT", "", "", policies);
	}

	public JSONObject putGroupSummary(String gid, String name,
			String description, String isActive) throws NexusClientException {
		// # Edit group. Group name, description, and whether the group is
		// active or not
		// # are the only things that can be set using this method.

		String url = "/groups/" + gid;
		JSONObject params = new JSONObject();

		try {

			if (!name.isEmpty()) {
				params.put("name", name);
			}
			if (!description.isEmpty()) {
				params.put("description", description);
			}
			if (isActive.equals("True")) {
				params.put("is_active", isActive);
			}

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return issueRestRequest(url, "PUT", "", "", params);
	}

	public JSONObject putMembershipStatusWrapper(UUID gid, String username,
			String newStatus, String expectedCurrent,
			String transitionErrorMessage, String newStatusReason)
			throws NexusClientException {

		JSONObject member = getGroupMember(gid, username);
		String email = "";
		String role = "";
		String status = "";
		String statusReason = "";

		try {
			if (!member.getString("status").equals(expectedCurrent)) {
				// raise StateTransitionError(member['status'], new_status,
				// transition_error_message)
			}
			member.put("status", newStatus);
			member.put("statusReason", newStatusReason);
			email = member.getString("email");
			role = member.getString("role");
			status = member.getString("status");
			statusReason = member.getString("status_reason");

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return putGroupMembership(gid.toString(), username, email, role,
				status, statusReason, "", "");
	}

	public JSONObject putUser(String username, JSONObject kwargs)
			throws NexusClientException {
		// # Edit existing user.

		try {
			kwargs.put("username", username);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}
		String path = "/users/" + username;

		return issueRestRequest(path, "PUT", "", "", kwargs);
	}

	public JSONObject putUserCustomFields(String username, JSONObject kwargs) throws NexusClientException {
		JSONObject content = getUser(username);

		try {
			content.put("custom_fields", kwargs);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}
		content.remove("username");
		return putUser(username, content);
	}

	public JSONObject putUserMembershipVisibility(String username,
			String newVisibility) throws NexusClientException {
		JSONObject policies = getUserPolicies(username);
		JSONObject visibilityPolicy;
		try {
			visibilityPolicy = (JSONObject) policies.getJSONObject(
					"user_membership_visibility").get("value");

			Iterator<?> keys = visibilityPolicy.keys();

			while (keys.hasNext()) {
				((JSONObject) visibilityPolicy.get((String) keys.next())).put(
						"value", newVisibility);
			}
			policies.getJSONObject("user_membership_visibility").put("value",
					visibilityPolicy);

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return putUserPolicies(username, policies);
	}

	public JSONObject putUserPolicies(String username, JSONObject policies) throws NexusClientException {
		String url = "/users/" + username + "/policies";
		return issueRestRequest(url, "PUT", "", "", policies);
	}

	public JSONObject rejectInvitation(UUID gid, String username,
			String statusReason) throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "rejected", "invited",
				"Only an invited user can reject an invitation.", "");
	}

	public JSONObject rejectPending(UUID gid, String username,
			String statusReason) throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "rejected", "pending",
				"Only possible to reject membership for pending users.", "");
	}

	public void setCommunity(String community) {
		this.community = community;
	}

	public void setIgnoreCertErrors(boolean ignoreCertErrors) {
		this.ignoreCertErrors = ignoreCertErrors;
	}
	
	public void setNexusApiHost(String nexusApiHost) {
		this.nexusApiHost = nexusApiHost;
	}

	public JSONObject setSinglePolicy(UUID gid, JSONObject policy,
			JSONArray newPolicyOptions) throws NexusClientException {
		// # Wrapper function for easily setting a single policy. For a given
		// policy,
		// # all policy options specified in new_policy_options are set to true,
		// # all others to false. new_policy_options may be a string for
		// single-value
		// # policies and must be a list for multi-value policies.

		JSONObject policies = getGroupPolicies(gid);
		JSONArray existingPolicyOptions;
		try {
			existingPolicyOptions = policies.getJSONArray("policy");

			for (int i = 0; i < existingPolicyOptions.length(); i++) {
				for (int j = 0; j < newPolicyOptions.length(); j++) {
					if (existingPolicyOptions
							.getJSONObject(i)
							.get("value")
							.equals(newPolicyOptions.getJSONObject(j).get(
									"value"))) {
						existingPolicyOptions.getJSONObject(i).put("value",
								"True");
					} else {
						existingPolicyOptions.getJSONObject(i).put("value",
								"False");
					}
				}
			}

		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return putGroupPolicies(gid, policies);
	}
	
	public JSONObject setSinglePolicy(UUID gid, JSONObject policy,
			String newPolicyOption) throws NexusClientException {
		// # Wrapper function for easily setting a single policy. For a given
		// policy,
		// # all policy options specified in new_policy_options are set to true,
		// # all others to false. new_policy_options may be a string for
		// single-value

		JSONArray newPolicyOptionsArray = new JSONArray();
		try {
			newPolicyOptionsArray.put(0, newPolicyOption);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return setSinglePolicy(gid, policy, newPolicyOptionsArray);
	}

	public JSONObject simpleCreateUser(String username, String acceptTerms,
			String optIn) throws NexusClientException {
		// # Wrapper function that only needs a username to create a user. If
		// you
		// # want full control, use post_user instead.

		String fullname, email, password;

		if (acceptTerms.equals("")) {
			acceptTerms = "True";
		}

		if (optIn.equals("")) {
			optIn = "True";
		}

		fullname = username + " " + (username + "son");
		email = username + "@" + username + "son.com";
		password = "test";

		JSONObject kwargs = new JSONObject();
		try {
			kwargs.put("accept_terms", acceptTerms);
			kwargs.put("optIn", optIn);
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

		return postUser(username, fullname, email, password, kwargs);
	}

	public JSONObject suspendGroupMember(UUID gid, String username,
			String newStatusReason) throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "suspended", "active",
				"Only active members can be suspended.", newStatusReason);
	}

	public JSONObject unsuspendGroupMember(UUID gid, String username,
			String newStatusReason) throws NexusClientException {
		return putMembershipStatusWrapper(gid, username, "active", "suspended",
				"Only suspended members can be unsuspended.", newStatusReason);
	}

	private JSONObject putGroupMembership(String url, String username,
			String email, String role, String status, String statusReason,
			String userDetails) throws NexusClientException {

		JSONObject params = new JSONObject();
		try {
			params.put("username", username);
			params.put("status", status);
			params.put("status_reason", status);
			params.put("role", role);
			params.put("email", email);

			// # last_changed needs to be set or validation will fail, but the
			// value
			// # will get overwritten by Graph anyway.
			params.put("last_changed", "2007-03-01T13:00:00");

			if (userDetails != null) {
				params.put("user", userDetails);
			}
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}
		return issueRestRequest(url, "PUT", "", "", params);
	}

	private String urlEncode(JSONObject parameters) {

		Iterator<?> keys = parameters.keys();
		String queryString = "";

		while (keys.hasNext()) {
			String key = (String) keys.next();
			try {
				String value = parameters.getString(key);
				queryString = queryString + URLEncoder.encode(key, "UTF-8")
						+ "=" + URLEncoder.encode(value, "UTF-8") + "&";
			} catch (UnsupportedEncodingException e) {
				logger.error("Unsupported Encoding Exception.");
				e.printStackTrace();
			} catch (JSONException e) {
				logger.error("JSON Exception.");
				e.printStackTrace();
			}
		}

		queryString = queryString.substring(0, queryString.length() - 2);

		return queryString;
	}

	protected NexusAuthenticator getAuthenticator() {
		return authenticator;
	}

	protected JSONObject issueRestRequest(String path)
			throws NexusClientException {
		return issueRestRequest(path, "", "", "", null);
	}

	protected JSONObject issueRestRequest(String path, NexusAuthenticator authenticator)
			throws NexusClientException {
		return issueRestRequest(path, "", "", "", null, authenticator);
	}

	protected JSONObject issueRestRequest(String path, String httpMethod,
			String contentType, String accept, JSONObject params)
			throws NexusClientException {
		return issueRestRequest(path, httpMethod, contentType, accept, params,
				getAuthenticator());
	}

	/**
	 * @param path
	 * @return JSON Response from action
	 * @throws NexusClientException
	 */
	protected JSONObject issueRestRequest(String path, String httpMethod,
			String contentType, String accept, JSONObject params,
			NexusAuthenticator auth) throws NexusClientException {

		JSONObject json = null;

		HttpsURLConnection connection;

		if (httpMethod.isEmpty()) {
			httpMethod = "GET";
		}
		if (contentType.isEmpty()) {
			contentType = "application/json";
		}
		if (accept.isEmpty()) {
			accept = "application/json";
		}
		int responseCode;

		try {

			URL url = new URL(getNexusApiUrl() + path);

			connection = (HttpsURLConnection) url.openConnection();

			if (ignoreCertErrors) {
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new SecureRandom());
				connection.setSSLSocketFactory(sc.getSocketFactory());
				connection.setHostnameVerifier(allHostsValid);
			}
			
			if (auth != null) {
				auth.authenticate(connection);
			}

			connection.setDoOutput(true);
			connection.setInstanceFollowRedirects(false);
			connection.setRequestMethod(httpMethod);
			connection.setRequestProperty("Content-Type", contentType);
			connection.setRequestProperty("Accept", accept);
			connection.setRequestProperty("X-Go-Community-Context", community);

			String body = "";

			if (params != null) {
				OutputStreamWriter out = new OutputStreamWriter(
						connection.getOutputStream());
				body = params.toString();
				out.write(body);
				logger.debug("Body:" + body);
				out.close();
			}

			responseCode = connection.getResponseCode();

		} catch (Exception e) {
			logger.error("Unhandled connection error:", e);
			throw new ValueErrorException();
		}

		logger.info("ConnectionURL: " + connection.getURL());

		if (responseCode == 403 || responseCode == 400) {
			logger.error("Access is denied.  Invalid credentials.");
			throw new InvalidCredentialsException();
		}
		if (responseCode == 404) {
			logger.error("URL not found.");
			throw new InvalidUrlException();
		}
		if (responseCode == 500) {
			logger.error("Internal Server Error.");
			throw new ValueErrorException();
		}
		if (responseCode != 200) {
			logger.info("Response code is: " + responseCode);
		}

		try {
			BufferedReader in = new BufferedReader(new InputStreamReader(
					connection.getInputStream()));
			String decodedString = in.readLine();

			json = new JSONObject(decodedString);
		} catch (JSONException e) {
			logger.error("JSON Error", e);
			throw new ValueErrorException();
		} catch (IOException e) {
			logger.error("IO Error", e);
			throw new ValueErrorException();
		}

		return json;
	}

	protected void setAuthenticator(NexusAuthenticator authenticator) {
		this.authenticator = authenticator;
	}

	/**
	 * @param currentUser the currentUser to set
	 */
	protected void setCurrentUser(JSONObject currentUser) {
		this.currentUser = currentUser;
	}

}