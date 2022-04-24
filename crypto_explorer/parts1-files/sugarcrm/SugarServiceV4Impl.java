/*
 * A Java client library to interact with the Sugar CRM REST API.
 * Copyright (C) 2013-2014 Tim Stephenson (tim@knowprocess.com)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.knowprocess.sugarcrm.internal;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;

import com.knowprocess.crm.CrmRecord;
import com.knowprocess.crm.CrmSession;
import com.knowprocess.sugarcrm.api.ArchivedEmail;
import com.knowprocess.sugarcrm.api.SugarAuthenticationException;
import com.knowprocess.sugarcrm.api.SugarException;
import com.knowprocess.sugarcrm.api.SugarService;
import com.knowprocess.sugarcrm.api.SugarSession;

public class SugarServiceV4Impl {

    public static final String SVC_URL_FRAGMENT = "service/v4/rest.php";
	private static final String NAME_VALUE_LIST_MARKER = "name_value_list";
	private static final String NAME_MARKER = "\"name\":\"";
	private static final String ID_MARKER = "\"id\":\"";
	private static final String VALUE_MARKER = "\"value\":\"";

	private Properties queries;
	private MessageDigest md;

	public SugarServiceV4Impl() throws IOException, NoSuchAlgorithmException {
		queries = new Properties();
		queries.load(getClass().getResourceAsStream("/queries.properties"));
		md = MessageDigest.getInstance("MD5");
	}

	public String login(SugarSession session) throws IOException {
		if (!session.isValid()) {
			throw new IllegalArgumentException(
					"Session is incompletely specified");
		}
		URL url = new URL(getServiceUrl(session.getSugarUrl()) + "?"
				+ getLoginPayload(session));
		return getIdFromGet(url);
	}

	protected String doGet(URL url) throws IOException {
		InputStream is = null;
		StringBuffer response = new StringBuffer();
		try {
			byte[] b = new byte[1024];
			is = (InputStream) url.getContent();
			while (is.read(b) != -1) {
				response.append(new String(b).trim());
			}
		} finally {
			try {
				is.close();
			} catch (NullPointerException e) {
				// Good chance this is a Jenkins environment calling localhost
				throw new IllegalStateException("Cannot connect to Sugar at: "
						+ url, e);
			}
		}
		return response.toString();
	}

	protected String getIdFromGet(URL url) throws IOException {
		return parseId(doGet(url));
	}

	private String parseId(String s) {
		// System.out.println("response: " + s);
		if (s.indexOf("Invalid Login") != -1) {
			throw new SugarAuthenticationException();
		} else if (s.trim().equals("null")) {
			throw new SugarException("No response received.");
		}
		int start = s.indexOf(ID_MARKER) + ID_MARKER.length();
		String id = s.substring(start, s.indexOf('"', start));
		return id;
	}

	protected String doPost(URL url, String urlParameters) throws IOException {
		System.out.println("POST to " + url + "\n  with " + urlParameters);
		InputStream is = null;
		StringBuffer response = new StringBuffer();
		try {
			HttpURLConnection connection = (HttpURLConnection) url
					.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setInstanceFollowRedirects(false);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type",
					"application/x-www-form-urlencoded");
			connection.setRequestProperty("charset", "utf-8");
			connection.setRequestProperty("Content-Length",
					"" + Integer.toString(urlParameters.getBytes().length));
			connection.setUseCaches(false);

			DataOutputStream wr = new DataOutputStream(
					connection.getOutputStream());
			wr.writeBytes(urlParameters);
			wr.flush();
			wr.close();
			byte[] b = new byte[1024];
			is = (InputStream) connection.getContent();
			// System.out.println("content length reported: "
			// + connection.getContentLength());
			while (is.read(b) != -1) {
				response.append(new String(b).trim());
			}
			System.out.println("content length found: "
					+ response.toString().length());
			connection.disconnect();
		} finally {
			try {
				is.close();
			} catch (Exception e) {
				;
			}
		}
		return response.toString();
	}

	protected String getIdFromPost(URL url, String urlParameters)
			throws IOException {
		return parseId(doPost(url, urlParameters));
	}

	public String setEntry(CrmSession session, String module,
			String nameValueList) throws IOException {
		URL url = new URL(getServiceUrl(session.getSugarUrl()));
		return getIdFromPost(url,
				getSetEntryPayload(session, module, nameValueList));
	}

	public String setRelationship(CrmSession session, String moduleName,
			String moduleId, String linkField, String linkId)
			throws IOException {
		return doPost(
				new URL(getServiceUrl(session.getSugarUrl())),
				getSetRelationshipPayload(session, moduleName, moduleId,
						linkField, linkId));
	}

	public CrmRecord getEntry(CrmSession session, String moduleName,
			String contactId, String selectFields) throws IOException {
		URL url = new URL(getServiceUrl(session.getSugarUrl()));
		String entry = doPost(
				url,
				getGetEntryPayload(session, moduleName, contactId, selectFields));
		return parseRecordFromSugarRepresentation(entry);
	}

    public List<CrmRecord> getRelationships(CrmSession session,
            String moduleName, String id, String linkedModule)
            throws IOException {
        URL url = new URL(getServiceUrl(session.getSugarUrl()));
        String entry = doPost(
                url,
                getGetRelationshipsPayload(session, moduleName, id,
                        linkedModule));
        return parseRecordsFromJson(entry);
    }

	protected CrmRecord parseRecordFromSugarRepresentation(String entry) {
		System.out.println("entry: " + entry);
		CrmRecord record = new CrmRecord();
		if (entry.contains(NAME_VALUE_LIST_MARKER)) {
			int lStart = entry.indexOf(NAME_VALUE_LIST_MARKER);
			entry = entry.substring(lStart + NAME_VALUE_LIST_MARKER.length()
					+ 2);
		}
		System.out.println("entry: " + entry);
		String[] nameValues = entry.split("\\{");
		for (String nameValue : nameValues) {
			System.out.println("parsing value from: " + nameValue);
			if (nameValue != null && !nameValue.equals("null")
					&& nameValue.length() > 0) {
				int nStart = nameValue.indexOf(NAME_MARKER)
						+ NAME_MARKER.length();
				int vStart = nameValue.indexOf(VALUE_MARKER)
						+ VALUE_MARKER.length();
                if (vStart != -1) {
                    try {
                        String val = nameValue.substring(vStart,
                                nameValue.indexOf("\"", vStart));
                        System.out.println(String.format("Found value: %1$s",
                                val));
                        if (val.equals("company_no_c")) {
                            System.err.println("TODO Remove this workaround");
                            record.setCustom(
                                    nameValue.substring(nStart,
                                            nameValue.indexOf("\"", nStart)),
                                    null);
                        } else if (val.trim().length() > 0) {
                            val = fixUrlIssue(val);
                            record.setCustom(
                                    nameValue.substring(nStart,
                                            nameValue.indexOf("\"", nStart)),
                                    val);
                        }
                    } catch (StringIndexOutOfBoundsException e) {
                        // object rather than simple child
                        // or could also be response is truncated which I have
                        // seen
                        // at 5079 chars (though sometimes over 6000)
                    }
				}
			}
		}
		return record;
	}

    /**
     * For some reason Sugar returns URLs like
     * <code>http://www.ergodigital.com/</code> as
     * <code>http:\/\/www.ergodigital.com\/</code>.
     * 
     * @param val
     * @return
     */
    private String fixUrlIssue(String val) {
        return val.replace("\\/", "/");
    }

    protected CrmRecord parseRecordFromJson1(String response) {
		JsonReader reader = Json.createReader(new StringReader(response));
		JsonObject value = reader.readObject();
		System.out.println("value:" + value);
		reader.close();

		CrmRecord record = new CrmRecord();
		for (Entry<String, JsonValue> entry : value.entrySet()) {
			if (entry.getValue() != null && !entry.getValue().equals("null")) {
				record.setCustom(entry.getKey(), entry.getValue());
			}
		}
		return record;
	}

	protected String getLoginPayload(SugarSession session)
			throws UnsupportedEncodingException {
		String query = queries.getProperty("login");
		return String.format(query, session.getUsername(),
				session.getUsername(), hash(session.getPassword()),
				SugarService.class.getName());
	}

	protected String hash(String plainPassword)
			throws UnsupportedEncodingException {
		md.reset();
		md.update(plainPassword.getBytes("UTF-8"));
		BigInteger bigInt = new BigInteger(1, md.digest());
		String hashtext = bigInt.toString(16);
		return hashtext;
	}

	protected String getServiceUrl(String sugarUrl) {
		if (sugarUrl.endsWith("/")) {
			return sugarUrl + SVC_URL_FRAGMENT;
		} else {
			return sugarUrl + "/" + SVC_URL_FRAGMENT;
		}
	}

	protected String getSetEntryPayload(CrmSession session, String module,
			String nameValueList) throws UnsupportedEncodingException {
		String query = queries.getProperty("set_entry");
		return String.format(query, session.getSessionId(), module,
				nameValueList);
	}

	protected String getGetEntryPayload(CrmSession session, String module,
			String entryId, String nameValueList)
			throws UnsupportedEncodingException {
		String query = queries.getProperty("get_entry");
		return String.format(query, session.getSessionId(), module, entryId,
				nameValueList);
	}

    protected String getGetRelationshipsPayload(CrmSession session,
            String module, String entryId, String linkedModule)
            throws UnsupportedEncodingException {
        String query = queries.getProperty("get_relationships");
        return String.format(query, session.getSessionId(), module, entryId,
                linkedModule);
    }

    protected String getSetRelationshipPayload(CrmSession session,
			String moduleName, String parentId, String linkField, String linkId) {
		String query = queries.getProperty("set_relationship");
		return String.format(query, session.getSessionId(), moduleName,
				parentId, linkField, linkId);
	}

	public String getModuleFields(CrmSession session, String moduleName)
			throws IOException {
		return doPost(new URL(getServiceUrl(session.getSugarUrl())),
				getModuleFieldsPayload(session, moduleName));
	}

	protected String getModuleFieldsPayload(CrmSession session,
			String moduleName) {
		String query = queries.getProperty("get_module_fields");
		return String.format(query, session.getSessionId(), moduleName);
	}

	public List<CrmRecord> search(CrmSession session, String module,
			CrmRecord query, int offset, int maxResults) throws IOException {
		URL url = new URL(getServiceUrl(session.getSugarUrl()));
		String response = doPost(url,
				getSearchPayload(session, module, query, offset, maxResults));
		return parseRecordsFromJson(response);
	}

	public List<CrmRecord> parseRecordsFromJson(String response) {
		System.out.println("response: " + response);
		JsonReader reader = Json.createReader(new StringReader(response));
		JsonObject value = reader.readObject();
		// System.out.println("value:" + value);
		reader.close();
		JsonArray array = value.getJsonArray("entry_list");
		ArrayList<CrmRecord> list = new ArrayList<CrmRecord>();
		for (Iterator<JsonValue> it = array.listIterator(); it.hasNext();) {
			JsonValue next = it.next();
			list.add(parseRecordFromSugarRepresentation(next.toString()));
			// list.add(new CrmRecord());
		}
		return list;
	}

	protected String getSearchPayload(CrmSession session, String moduleName,
			CrmRecord queryObject, int offset, int maxResults) {
		String query = queries.getProperty("search_by_module");
		return String.format(query, session.getSessionId(), moduleName,
				queryObject.getSearchString(), offset, maxResults,
				session.getUsername(), "");
	}

	public List<CrmRecord> getEntryList(CrmSession session, String moduleName,
			CrmRecord query, String orderByClause, int offset, int maxResults)
			throws IOException {
		URL url = new URL(getServiceUrl(session.getSugarUrl()));
		String response = doPost(
				url,
				getGetEntryListPayload(session, moduleName,
						query.getWhereClause(moduleName.toLowerCase()),
						orderByClause, query.getSelectFields(), offset,
						maxResults));
		return parseRecordsFromJson(response);
	}

	protected String getGetEntryListPayload(CrmSession session, String module,
			String whereClause, String orderByClause, String selectFields,
			int offset, int maxResults) {
		String query = queries.getProperty("get_entry_list");
		return String.format(query, session.getSessionId(), module,
				whereClause, orderByClause, selectFields, offset, maxResults);
	}

	public String toJson(List<CrmRecord> list) {
		StringBuilder sb = new StringBuilder("[");
		for (CrmRecord crmRecord : list) {
			sb.append(crmRecord.toJson());
		}
		return sb.append("]").toString();
	}

	public CrmRecord archiveEmail(CrmSession session, ArchivedEmail email)
			throws IOException {
		URL url = new URL(getServiceUrl(session.getSugarUrl()));
		String response = doPost(url, getArchiveEmailPayload(session, email));
		System.out.println("response: " + response);
		String id = parseId(response);
		email.setId(id);
		return email;
	}

	protected String getArchiveEmailPayload(CrmSession session,
			ArchivedEmail email) {
		String query = queries.getProperty("snip_import_emails");
		String cmd = String.format(query, session.getSessionId(),
				email.getSubject(), email.getFrom(), email.getBody(),
				"<html></html>", email.getTo(), "", "", "2014-01-31 14:30:19");
		System.out.println("cmd: " + cmd);
		return cmd;
	}

    public String getAvailableModules(SugarSession session, String filter)
            throws IOException {
        if (filter == null
                || (!filter.equals("all") && !filter.equals("default") && !filter
                        .equals("mobile"))) {
            filter = "default";
        }
        return doPost(new URL(getServiceUrl(session.getSugarUrl())),
                getAvailableModulesPayload(session, filter));
    }

    protected String getAvailableModulesPayload(CrmSession session,
            String filter) {
        String query = queries.getProperty("get_available_modules");
        return String.format(query, session.getSessionId(), filter);
    }
}
