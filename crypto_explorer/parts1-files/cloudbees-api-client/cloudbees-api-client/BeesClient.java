package com.cloudbees.api;

import com.cloudbees.upload.ArchiveUtils;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.json.JettisonMappedXmlDriver;
import org.codehaus.jettison.json.JSONObject;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Fabian Donze
 */
public class BeesClient extends BeesClientBase
{
    static Logger logger = Logger.getLogger(BeesClient.class.getSimpleName());


    public BeesClient(BeesClientConfiguration beesClientConfiguration) {
        super(beesClientConfiguration);
    }
    public BeesClient(String server, String apikey, String secret,
                      String format, String version)
    {
        super(server, apikey, encodePassword(secret, version), format,
            version);
    }

    public SayHelloResponse sayHello(String message) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("message", message);
        String url = getRequestURL("say.hello", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        SayHelloResponse helloResponse =
            (SayHelloResponse)readResponse(response);
        return helloResponse;
    }

    public ApplicationGetSourceUrlResponse applicationGetSourceUrl(
        String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.getSourceUrl", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationGetSourceUrlResponse apiResponse =
            (ApplicationGetSourceUrlResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationDeleteResponse applicationDelete(String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.delete", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationDeleteResponse apiResponse =
            (ApplicationDeleteResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationRestartResponse applicationRestart(String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.restart", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationRestartResponse apiResponse =
            (ApplicationRestartResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationStatusResponse applicationStart(String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.start", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationStatusResponse apiResponse =
            (ApplicationStatusResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationStatusResponse applicationStop(String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.stop", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationStatusResponse apiResponse =
            (ApplicationStatusResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationListResponse applicationList() throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        String url = getRequestURL("application.list", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationListResponse apiResponse =
            (ApplicationListResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationInfo applicationInfo(String appId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.info", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationInfoResponse apiResponse =
            (ApplicationInfoResponse)readResponse(response);
        return apiResponse.getApplicationInfo();
    }

    public ApplicationSetMetaResponse applicationSetMeta(String appId,
        Map<String, String> metaAttrs) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.putAll(metaAttrs);
        params.put("app_id", appId);
        String url = getRequestURL("application.setMeta", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        ApplicationSetMetaResponse apiResponse =
            (ApplicationSetMetaResponse)readResponse(response);
        return apiResponse;
    }

    public ApplicationDeployArchiveResponse applicationDeployEar(
        String appId, String environment, String description, String earFile,
        String srcFile, UploadProgress progress) throws Exception
    {
        String archiveType = "ear";
        return applicationDeployArchive(appId, environment, description,
            earFile, srcFile, archiveType, false, progress);
    }
    public ApplicationDeployArchiveResponse applicationDeployWar(
        String appId, String environment, String description, String warFile,
        String srcFile, UploadProgress progress) throws Exception
    {
        return applicationDeployWar(appId, environment, description, warFile,
                srcFile, true, progress);
    }
    public ApplicationDeployArchiveResponse applicationDeployWar(
        String appId, String environment, String description, String warFile,
        String srcFile, boolean deltaDeploy, UploadProgress progress) throws Exception
    {
        String archiveType = "war";
        return applicationDeployArchive(appId, environment, description,
            warFile, srcFile, archiveType, deltaDeploy, progress);
    }

    public ApplicationDeployArchiveResponse applicationDeployArchive(
            String appId, String environment, String description, String earFile,
            String srcFile, String archiveType, UploadProgress progress) throws Exception
    {
        return applicationDeployArchive(appId, environment, description, earFile, srcFile, archiveType, false, progress);
    }
    public ApplicationDeployArchiveResponse applicationDeployArchive(
            String appId, String environment, String description, String earFile,
            String srcFile, String archiveType, boolean deltaDeploy, UploadProgress progress) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        Map<String, File> fileParams = new HashMap<String, File>();
        params.put("app_id", appId);

        File archiveFile = new File(earFile);

        // Currently only support WAR file for delta upload
        boolean deployDelta = false;
        // Create delta deploy File
        if (deltaDeploy && archiveType.equals("war")) {
            trace("Get existing checksums");
            ApplicationCheckSumsResponse applicationCheckSumsResponse = applicationCheckSums(appId, false);
            if (logger.isLoggable(Level.FINER)) {
                for (Map.Entry<String, Long> entry : applicationCheckSumsResponse.getCheckSums().entrySet()) {
                    logger.finer("Entry: " + entry.getKey() + " CRC: " + entry.getValue());
                }
            }
            if (applicationCheckSumsResponse.getCheckSums().size() == 0) {
                trace("No existing checksums, upload full archive");
            } else {
                trace("Creating Delta archive for: " + archiveFile);
                archiveFile = ArchiveUtils.createDeltaWarFile(applicationCheckSumsResponse.getCheckSums(), archiveFile, archiveFile.getParent());
                deployDelta = true;
                trace("Uploading delta archive: " + archiveFile);
            }
        }

        File archiveFileSrc = srcFile != null ? new File(srcFile) : null;
        long uploadSize = archiveFile.length();
        if (archiveFileSrc != null)
            uploadSize += archiveFileSrc.length();

        fileParams.put("archive", archiveFile);
        params.put("archive_type", archiveType);

        if (environment != null)
            params.put("environment", environment);

        if (description != null)
            params.put("description", description);

        if (archiveFileSrc != null)
            fileParams.put("src", archiveFileSrc);

        // extend the deploy invocation timeout to 4 hours
        long expireTime = System.currentTimeMillis() + 4 * 60 * 60 * 1000;
        params.put("expires", new Long(expireTime / 1000).toString());

        String url = getApiUrl("application.deployArchive").toString();
        params.put("action", "application.deployArchive");
        trace("API call: " + url);
        String response = executeUpload(url, params, fileParams, progress);
        try {
            ApplicationDeployArchiveResponse apiResponse =
                (ApplicationDeployArchiveResponse)readResponse(response);

            return apiResponse;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Invalid application deployment response: " + appId, e);
            logger.log(Level.FINE, "Deploy response trace: " + response);
            throw e;
        } finally {
            // Delete the delta archive file
            if (deployDelta)
                archiveFile.delete();
        }
    }

    public ApplicationCheckSumsResponse applicationCheckSums(String appId) throws Exception
    {
        return applicationCheckSums(appId, true);
    }
    public ApplicationCheckSumsResponse applicationCheckSums(String appId, boolean traceResponse) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        String url = getRequestURL("application.checkSums", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        if (traceResponse)
            traceResponse(response);
        ApplicationCheckSumsResponse apiResponse =
            (ApplicationCheckSumsResponse)readResponse(response);
        return apiResponse;
    }

    public DatabaseCreateResponse databaseCreate(String domain, String dbId,
        String username, String password) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("database_id", dbId);
        params.put("database_username", username);
        params.put("database_password", password);
        params.put("domain", domain);
        String url = getRequestURL("database.create", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        DatabaseCreateResponse apiResponse =
            (DatabaseCreateResponse)readResponse(response);
        return apiResponse;
    }

    public DatabaseDeleteResponse databaseDelete(String dbId) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("database_id", dbId);
        String url = getRequestURL("database.delete", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        DatabaseDeleteResponse apiResponse =
            (DatabaseDeleteResponse)readResponse(response);
        return apiResponse;
    }

    public DatabaseInfo databaseInfo(String dbId, boolean fetchPassword) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("database_id", dbId);
        params.put("fetch_password", ((Boolean)fetchPassword).toString());
        String url = getRequestURL("database.info", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        DatabaseInfoResponse apiResponse =
            (DatabaseInfoResponse)readResponse(response);
        return apiResponse.getDatabaseInfo();
    }

    public DatabaseListResponse databaseList() throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        String url = getRequestURL("database.list", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        DatabaseListResponse apiResponse =
            (DatabaseListResponse)readResponse(response);
        return apiResponse;
    }

    public AccountKeysResponse accountKeys(String domain, String user, String password) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("user", user);
        params.put("password", password);
        if (domain != null) params.put("domain", domain);
        String url = getRequestURL("account.keys", params);
        String response = executeRequest(url);
        AccountKeysResponse apiResponse =
            (AccountKeysResponse)readResponse(response);
        return apiResponse;
    }

    public AccountListResponse accountList() throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        String url = getRequestURL("account.list", params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        AccountListResponse apiResponse =
            (AccountListResponse)readResponse(response);
        return apiResponse;
    }

    private String createParameter(Map<String,String>parameters) {
        if (parameters == null)
            parameters = new HashMap<String, String>();
        JSONObject jsonObject = new JSONObject(parameters);
        return jsonObject.toString();
    }

    public void tailLog(String appId, String logName, OutputStream out) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put("app_id", appId);
        params.put("log_name", logName);
        String url = getRequestURL("tail", params, false);
        trace("API call: " + url);
        InputStream input = executeCometRequest(url);

        byte[] bytes = new byte[1024];
        int numRead = input.read(bytes);
        while (numRead != -1) {
            out.write(bytes, 0, numRead);
            numRead = input.read(bytes);
        }
    }

    public String call(String action, Map<String, String> params) throws Exception
    {
        String url = getRequestURL(action, params);
        trace("API call: " + url);
        String response = executeRequest(url);
        traceResponse(response);
        return response;
    }

    protected XStream getXStream() throws Exception {
        XStream xstream;
        if (format.equals("json")) {
            xstream = new XStream(new JettisonMappedXmlDriver());
        } else if (format.equals("xml")) {
            xstream = new XStream();
        } else {
            throw new Exception("Unknown format: " + format);
        }

        xstream.processAnnotations(SayHelloResponse.class);
        xstream.processAnnotations(ApplicationGetSourceUrlResponse.class);
        xstream.processAnnotations(ApplicationDeleteResponse.class);
        xstream.processAnnotations(ApplicationDeployResponse.class);
        xstream.processAnnotations(ApplicationDeployArchiveResponse.class);
        xstream.processAnnotations(ApplicationInstallResponse.class);
        xstream.processAnnotations(ApplicationInfo.class);
        xstream.processAnnotations(ApplicationInfoResponse.class);
        xstream.processAnnotations(ApplicationListResponse.class);
        xstream.processAnnotations(ApplicationRestartResponse.class);
        xstream.processAnnotations(ApplicationStatusResponse.class);
        xstream.processAnnotations(ApplicationSetMetaResponse.class);
        xstream.processAnnotations(ApplicationCheckSumsResponse.class);
        xstream.processAnnotations(DatabaseCreateResponse.class);
        xstream.processAnnotations(DatabaseDeleteResponse.class);
        xstream.processAnnotations(DatabaseInfo.class);
        xstream.processAnnotations(DatabaseInfoResponse.class);
        xstream.processAnnotations(DatabaseListResponse.class);
        xstream.processAnnotations(ErrorResponse.class);
        xstream.processAnnotations(AccountKeysResponse.class);
        xstream.processAnnotations(AccountInfo.class);
        xstream.processAnnotations(AccountListResponse.class);

        // Hack to fix backward compatibility
        xstream.alias("net.stax.api.ApplicationStatusResponse", ApplicationStatusResponse.class);
        xstream.alias("net.stax.api.ApplicationSetMetaResponse", ApplicationSetMetaResponse.class);

        return xstream;
    }

    protected Object readResponse(String response) throws Exception
    {
        Object obj = getXStream().fromXML(response);
        if (obj instanceof ErrorResponse) {
            throw new BeesClientException((ErrorResponse)obj);
        }
        return obj;
    }

    public static String encodePassword(String password, String version)
    {
        if (version.equals("0.1")) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA");
                byte[] shaBytes = sha.digest(password.getBytes("UTF8"));
                StringBuffer hex = new StringBuffer();
                for (int i = 0; i < shaBytes.length; ++i) {
                    hex.append(Integer.toHexString(
                        (shaBytes[i] & 0xFF) | 0x100).substring(1, 3));
                }

                return hex.toString();
            } catch (NoSuchAlgorithmException e) {
            } catch (UnsupportedEncodingException e) {
            }
            return null;
        } else
            return password;
    }

    public void mainCall(String[] args) throws Exception
    {
        Map<String, String> params = new HashMap<String, String>();
        int argIndex = 0;
        if (argIndex < args.length) {
            String action = args[argIndex++];
            for (; argIndex < args.length; argIndex++) {
                String arg = args[argIndex];
                String[] pair = arg.split("=", 2);
                if (pair.length < 2)
                    throw new BeesClient.UsageError("Marlformed call parameter pair: " +
                        arg);
                params.put(pair[0], pair[1]);
            }
            String response = call(action, params);
            System.out.println(response);
        } else
            throw new BeesClient.UsageError("Missing required action argument");
    }

    public void main(String[] args) throws Exception
    {
        int argIndex = 0;
        Map<String, String> options = new HashMap<String, String>();
        for (; argIndex < args.length; argIndex++) {
            String arg = args[argIndex];
            if (arg.startsWith("-")) {
                if (arg.equals("--call") || arg.equals("-c"))
                    options.put("operation", arg);
                else if (arg.equals("--username") || arg.equals("-u"))
                    options.put("username", arg);
                else if (arg.equals("--password") || arg.equals("-p"))
                    options.put("password", arg);
                else if (arg.equals("--url") || arg.equals("-u"))
                    options.put("url", arg);
                else
                    throw new BeesClient.UsageError("Unsupported option: " + arg);
            } else {
                break;
            }
        }

        String operation = getRequiredOption("operation", options);
        BeesClient client =
            new BeesClient(getRequiredOption("url", options),
                getRequiredOption("username", options), getRequiredOption(
                    "password", options), "0.1", "1.0");

        if (operation.equals("call")) {
            String[] subArgs = new String[args.length - argIndex];
            for (int i = 0; i < subArgs.length; i++) {
                subArgs[i] = args[argIndex++];
            }
            client.main(subArgs);
        }
    }

    private static String getRequiredOption(String optionName,
        Map<String, String> options) throws BeesClient.UsageError
    {
        if (options.containsKey(optionName))
            return options.get(optionName);
        else
            throw new BeesClient.UsageError("Missing required flag: --" + optionName);
    }

    public static class UsageError extends Exception
    {
        UsageError(String reason)
        {
            super(reason);
        }
    }
}

