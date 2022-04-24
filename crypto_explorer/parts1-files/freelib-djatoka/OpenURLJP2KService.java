/*
 * Copyright (c) 2008 Los Alamos National Security, LLC.
 * 
 * Los Alamos National Laboratory Research Library Digital Library Research &
 * Prototyping Team
 * 
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

package gov.lanl.adore.djatoka.openurl;

import gov.lanl.adore.djatoka.DjatokaDecodeParam;
import gov.lanl.adore.djatoka.DjatokaException;
import gov.lanl.adore.djatoka.DjatokaExtractProcessor;
import gov.lanl.adore.djatoka.io.FormatConstants;
import gov.lanl.adore.djatoka.kdu.KduExtractExe;
import gov.lanl.adore.djatoka.plugin.ITransformPlugIn;
import gov.lanl.adore.djatoka.util.IOUtils;
import gov.lanl.adore.djatoka.util.ImageRecord;
import gov.lanl.util.HttpDate;
import info.freelibrary.djatoka.util.CacheUtils;
import info.openurl.oom.ContextObject;
import info.openurl.oom.OpenURLRequest;
import info.openurl.oom.OpenURLRequestProcessor;
import info.openurl.oom.OpenURLResponse;
import info.openurl.oom.Service;
import info.openurl.oom.config.ClassConfig;
import info.openurl.oom.config.OpenURLConfig;
import info.openurl.oom.entities.Referent;
import info.openurl.oom.entities.ServiceType;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import org.oclc.oomRef.descriptors.ByValueMetadataImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The OpenURLJP2KService OpenURL Service
 * 
 * @author Ryan Chute
 */
public class OpenURLJP2KService implements Service, FormatConstants {

    private static Logger LOGGER = LoggerFactory
	    .getLogger(OpenURLJP2KService.class);
    private static final String DEFAULT_IMPL_CLASS = SimpleListResolver.class
	    .getCanonicalName();
    private static final String PROPS_REQUESTER = "requester";
    private static final String PROPS_REFERRING_ENTITY = "referringEntity";
    private static final String PROPS_KEY_IMPL_CLASS = "OpenURLJP2KService.referentResolverImpl";
    private static final String PROPS_KEY_CACHE_ENABLED = "OpenURLJP2KService.cacheEnabled";
    private static final String PROPS_KEY_CACHE_TMPDIR = "OpenURLJP2KService.cacheTmpDir";
    private static final String PROPS_KEY_TRANSFORM = "OpenURLJP2KService.transformPlugin";
    private static final String PROPS_KEY_CACHE_SIZE = "OpenURLJP2KService.cacheSize";
    private static final String PROP_KEY_CACHE_MAX_PIXELS = "OpenURLJP2KService.cacheImageMaxPixels";
    private static final String SVC_ID = "info:lanl-repo/svc/getRegion";
    private static final String DEFAULT_CACHE_SIZE = "1000";
    private static final int DEFAULT_CACHE_MAXPIXELS = 100000;

    private static String implClass = null;
    private static Properties props = new Properties();
    private static boolean init = false;
    private static boolean cacheTiles = true;
    private static boolean transformCheck = false;
    private static ITransformPlugIn transform;
    private static String cacheDir = null;
    private static TileCacheManager<String, String> tileCache;
    private static DjatokaExtractProcessor extractor;
    private static int maxPixels = DEFAULT_CACHE_MAXPIXELS;

    /**
     * Construct an info:lanl-repo/svc/getRegion web service class. Initializes
     * Referent Resolver instance using OpenURLJP2KService.referentResolverImpl
     * property.
     * 
     * @param openURLConfig
     *            OOM Properties forwarded from OpenURLServlet
     * @param classConfig
     *            Implementation Properties forwarded from OpenURLServlet
     * @throws ResolverException
     */
    public OpenURLJP2KService(OpenURLConfig openURLConfig,
	    ClassConfig classConfig) throws ResolverException {
	try {
	    if (!init) {
		props = IOUtils.loadConfigByCP(classConfig.getArg("props"));
		if (!ReferentManager.isInit()) {
		    implClass = props.getProperty(PROPS_KEY_IMPL_CLASS,
			    DEFAULT_IMPL_CLASS);
		    ReferentManager.init(
			    (IReferentResolver) Class.forName(implClass)
				    .newInstance(), props);
		}
		cacheDir = props.getProperty(PROPS_KEY_CACHE_TMPDIR);
		if (props.getProperty(PROPS_KEY_CACHE_ENABLED) != null)
		    cacheTiles = Boolean.parseBoolean(props
			    .getProperty(PROPS_KEY_CACHE_ENABLED));
		if (cacheTiles) {
		    int cacheSize = Integer.parseInt(props.getProperty(
			    PROPS_KEY_CACHE_SIZE, DEFAULT_CACHE_SIZE));
		    tileCache = new TileCacheManager<String, String>(cacheSize);
		}
		if (props.getProperty(PROPS_KEY_TRANSFORM) != null) {
		    transformCheck = true;
		    String transClass = props.getProperty(PROPS_KEY_TRANSFORM);
		    transform = (ITransformPlugIn) Class.forName(transClass)
			    .newInstance();
		    transform.setup(props);
		}
		if (props.getProperty(PROP_KEY_CACHE_MAX_PIXELS) != null)
		    maxPixels = Integer.parseInt(props
			    .getProperty(PROP_KEY_CACHE_MAX_PIXELS));
		extractor = new DjatokaExtractProcessor(new KduExtractExe());
		init = true;
	    }
	}
	catch (IOException e) {
	    LOGGER.error(e.getMessage(), e);
	    throw new ResolverException(
		    "Error attempting to open props file from classpath, disabling "
			    + SVC_ID + " : " + e.getMessage());
	}
	catch (Exception e) {
	    LOGGER.error(e.getMessage(), e);
	    throw new ResolverException(
		    "Unable to inititalize implementation: "
			    + props.getProperty(implClass) + " - "
			    + e.getMessage());
	}
    }

    /**
     * Returns the OpenURL service identifier for this implementation of
     * info.openurl.oom.Service
     */
    public URI getServiceID() throws URISyntaxException {
	return new URI(SVC_ID);
    }

    public static boolean removeFromTileCache(String aCacheID) {
	return tileCache.remove(aCacheID) != null;
    }

    /**
     * Returns the OpenURLResponse consisting of an image bitstream to be
     * rendered on the client. Having obtained a result, this method is then
     * responsible for transforming it into an OpenURLResponse that acts as a
     * proxy for HttpServletResponse.
     */
    public OpenURLResponse resolve(ServiceType serviceType,
	    ContextObject contextObject, OpenURLRequest openURLRequest,
	    OpenURLRequestProcessor processor) {
	String djatokaCacheFile = null;
	String responseFormat = null;
	String format = "image/jpeg";
	int status = HttpServletResponse.SC_OK;
	HashMap<String, String> kev = setServiceValues(contextObject);
	DjatokaDecodeParam params = new DjatokaDecodeParam();
	String id = null;

	if (kev.containsKey("region")) params.setRegion(kev.get("region"));
	if (kev.containsKey("format")) {
	    format = kev.get("format");
	    if (!format.startsWith("image")) {
		// ignoring invalid format identifier
		format = "image/jpeg";
	    }
	}
	if (kev.containsKey("level"))
	    params.setLevel(Integer.parseInt(kev.get("level")));
	if (kev.containsKey("rotate"))
	    params.setRotationDegree(Integer.parseInt(kev.get("rotate")));
	if (kev.containsKey("scale")) {
	    String[] v = kev.get("scale").split(",");
	    if (v.length == 1) {
		if (v[0].contains("."))
		    params.setScalingFactor(Double.parseDouble(v[0]));
		else {
		    int[] dims = new int[] { -1, Integer.parseInt(v[0]) };
		    params.setScalingDimensions(dims);
		}
	    }
	    else if (v.length == 2) {
		int[] dims = new int[] { Integer.parseInt(v[0]),
			Integer.parseInt(v[1]) };
		params.setScalingDimensions(dims);
	    }
	}
	if (kev.containsKey("clayer") && kev.get("clayer") != null) {
	    int clayer = Integer.parseInt(kev.get("clayer"));
	    if (clayer > 0) params.setCompositingLayer(clayer);
	}
	responseFormat = format;

	byte[] bytes = null;

	/*
	 * DEAD CODE: responseFormat set right above -- TODO: remove if
	 * (responseFormat == null) { try { bytes =
	 * ("Output Format Not Supported").getBytes("UTF-8"); } catch
	 * (UnsupportedEncodingException e) { e.printStackTrace(); }
	 * responseFormat = "text/plain"; status =
	 * HttpServletResponse.SC_NOT_FOUND; } else
	 */

	if (params.getRegion() != null && params.getRegion().contains("-")) {
	    try {
		bytes = ("Negative Region Arguments are not supported.")
			.getBytes("UTF-8");
	    }
	    catch (UnsupportedEncodingException e) {
		e.printStackTrace();
	    }

	    responseFormat = "text/plain";
	    status = HttpServletResponse.SC_NOT_FOUND;
	}
	else {
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("Service has a valid region request");
	    }

	    try {
		Referent referent = contextObject.getReferent();
		ImageRecord r = ReferentManager.getImageRecord(referent);

		if (LOGGER.isDebugEnabled() && r != null) {
		    LOGGER.debug("Retrieving ImageRecord for: {}",
			    r.getIdentifier());
		}

		if (r != null) {
		    if (transformCheck && transform != null) {
			HashMap<String, String> instProps = new HashMap<String, String>();
			if (r.getInstProps() != null)
			    instProps.putAll(r.getInstProps());
			if (contextObject.getRequesters().length > 0
				&& contextObject.getRequesters()[0]
					.getDescriptors().length > 0) {
			    String requester = contextObject.getRequesters()[0]
				    .getDescriptors()[0].toString();
			    instProps.put(PROPS_REQUESTER, requester);
			}
			if (contextObject.getReferringEntities().length > 0
				&& contextObject.getReferringEntities()[0]
					.getDescriptors().length > 0)
			    instProps.put(PROPS_REFERRING_ENTITY,
				    contextObject.getReferringEntities()[0]
					    .getDescriptors()[0].toString());
			if (instProps.size() > 0)
			    transform.setInstanceProps(instProps);
			params.setTransform(transform);
		    }
		    if (!cacheTiles || !isCacheable(params)) {
			if (LOGGER.isWarnEnabled()) {
			    LOGGER.warn("Not using the OpenURL layer cache");
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			extractor.extractImage(r.getImageFile(), baos, params,
				format);
			bytes = baos.toByteArray();
			baos.close();
		    }
		    else {
			String ext = getExtension(format);
			String hash = getTileHash(r, params);
			String file = tileCache.get(hash + ext);
			File f;

			id = r.getIdentifier();

			if (file == null
				|| (file != null
					&& !(f = new File(file)).exists() && f
					.length() > 0)) {
			    if (cacheDir != null) {
				File cacheDirFile = new File(cacheDir);

				// If our cache dir doesn't exist, create it
				if (!cacheDirFile.exists()) {
				    cacheDirFile.mkdirs();
				}

				f = File.createTempFile(
					"cache" + hash.hashCode() + "-", "."
						+ ext, cacheDirFile);
			    }
			    else {
				f = File.createTempFile(
					"cache" + hash.hashCode() + "-", "."
						+ ext);
			    }

			    if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Temp file created: {}", f);
			    }

			    f.deleteOnExit();
			    file = f.getAbsolutePath();
			    djatokaCacheFile = file;

			    extractor.extractImage(r.getImageFile(), file,
				    params, format);

			    if (tileCache.get(hash + ext) == null) {
				tileCache.put(hash + ext, file);
				bytes = IOUtils.getBytesFromFile(f);

				if (LOGGER.isDebugEnabled()) {
				    LOGGER.debug("makingTile: " + file + " "
					    + bytes.length + " params: "
					    + params);
				}
			    }
			    else {
				// Handles simultaneous request on separate
				// thread, ignores cache.
				bytes = IOUtils.getBytesFromFile(f);
				f.delete();

				if (LOGGER.isDebugEnabled()) {
				    LOGGER.debug("tempTile: " + file + " "
					    + bytes.length + " params: "
					    + params);
				}
			    }
			}
			else {
			    bytes = IOUtils.getBytesFromFile(new File(file));

			    if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("tileCache: " + file + " "
					+ bytes.length);
			    }

			    djatokaCacheFile = file;
			}
		    }
		}
		else if (LOGGER.isWarnEnabled()) {
		    LOGGER.warn("Unable to retrieve ImageRecord");
		}
	    }
	    catch (ResolverException e) {
		LOGGER.error(e.getMessage(), e);
		bytes = e.getMessage().getBytes();
		responseFormat = "text/plain";
		status = HttpServletResponse.SC_NOT_FOUND;
	    }
	    catch (DjatokaException e) {
		LOGGER.error(e.getMessage(), e);
		bytes = e.getMessage().getBytes();
		responseFormat = "text/plain";
		status = HttpServletResponse.SC_NOT_FOUND;
	    }
	    catch (Exception e) {
		LOGGER.error(e.getMessage(), e);
		bytes = e.getMessage().getBytes();
		responseFormat = "text/plain";
		status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
	    }
	}

	if (bytes == null || bytes.length == 0) {
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("No bytes found!");
	    }

	    bytes = "".getBytes();
	    responseFormat = "text/plain";
	    status = HttpServletResponse.SC_NOT_FOUND;
	}

	HashMap<String, String> header_map = new HashMap<String, String>();
	header_map.put("Content-Length", bytes.length + "");
	header_map.put("Date", HttpDate.getHttpDate());

	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("Getting OpenURLResponse...");
	}

	OpenURLResponse response = new OpenURLResponse(status, responseFormat,
		bytes, header_map);

	// Record where our cache file was (if we had/created one)
	if (djatokaCacheFile != null) {
	    int[] dims = params.getScalingDimensions();
	    String scale = dims != null ? Integer.toString(dims[1]) : "";
	    String level = Integer.toString(params.getLevel());
	    String region = params.getRegion();
	    String ext = getExtension(format);
	    String hash;

	    try {
		hash = getTileHash(id, params);
	    }
	    catch (Exception details) {
		if (LOGGER.isErrorEnabled()) {
		    LOGGER.error(details.getMessage(), details);
		}

		hash = null;
	    }

	    id = id + "_" + CacheUtils.getFileName(level, scale, region);

	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("OpenURL service: [ {} | {} | {} ] = {}",
			new String[] { level, scale, region, id });
	    }

	    if (hash != null) {
		Map sessionMap = response.getSessionMap();
		String cacheName = hash + ext;

		if (LOGGER.isDebugEnabled()) {
		    LOGGER.debug("Setting cache session data [ {} | {} ]",
			    new String[] { id, djatokaCacheFile });
		}

		sessionMap.put(id, djatokaCacheFile);
		sessionMap.put(djatokaCacheFile, cacheName);
	    }
	}
	else if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("djatokaCacheFile variable is null");
	}

	return response;
    }

    private boolean isCacheable(DjatokaDecodeParam params) {
	if (transformCheck && params.getTransform().isTransformable())
	    return false;
	if (params.getScalingFactor() != 1.0) {
	    if (LOGGER.isDebugEnabled()) {
		LOGGER.debug("NOT CACHING BECAUSE SCALING FACTOR != 1.0");
	    }

	    return false;
	}
	/*
	 * Commented out below because we want to cache them all; we're working
	 * with openseadragon and will have a fixed/limited number of derivative
	 * files...
	 * 
	 * if (params.getScalingDimensions() != null) { int[] sd =
	 * params.getScalingDimensions(); if (sd.length == 1 && sd[0] >=
	 * maxPixels/2) return false; if (sd.length == 2 && (sd[0] * sd[1]) >=
	 * maxPixels) return false; } if (params.getRegion() != null) { String[]
	 * r = params.getRegion().split(","); if (r.length == 4) { int h =
	 * Integer.parseInt(r[2]); int w = Integer.parseInt(r[3]); if ((h * w)
	 * >= maxPixels) return false; } }
	 */

	return true;
    }

    private static final String getTileHash(ImageRecord r,
	    DjatokaDecodeParam params) throws Exception {
	return getTileHash(r.getIdentifier(), params);
    }

    private static final String getTileHash(String id, DjatokaDecodeParam params)
	    throws Exception {
	int level = params.getLevel();
	String region = params.getRegion();
	int rotateDegree = params.getRotationDegree();
	double scalingFactor = params.getScalingFactor();
	int[] scalingDims = params.getScalingDimensions();
	String scale = "";
	if (scalingDims != null && scalingDims.length == 1)
	    scale = scalingDims[0] + "";
	if (scalingDims != null && scalingDims.length == 2)
	    scale = scalingDims[0] + "," + scalingDims[1];
	int clayer = params.getCompositingLayer();
	String rft_id = id + "|" + level + "|" + region + "|" + rotateDegree
		+ "|" + scalingFactor + "|" + scale + "|" + clayer;
	MessageDigest complete = MessageDigest.getInstance("SHA1");
	return new String(complete.digest(rft_id.getBytes()));
    }

    private static final String getExtension(String mimetype) {
	if (mimetype.equals(FORMAT_MIMEYPE_JPEG)) return FORMAT_ID_JPG;
	if (mimetype.equals(FORMAT_MIMEYPE_PNG)) return FORMAT_ID_PNG;
	if (mimetype.equals(FORMAT_MIMEYPE_GIF)) return FORMAT_ID_GIF;
	if (mimetype.equals(FORMAT_MIMEYPE_PNM)) return FORMAT_ID_PNM;
	if (mimetype.equals(FORMAT_MIMEYPE_JP2)) return FORMAT_ID_JP2;
	if (mimetype.equals(FORMAT_MIMEYPE_JPX)) return FORMAT_ID_JPX;
	if (mimetype.equals(FORMAT_MIMEYPE_JPM)) return FORMAT_ID_JP2;
	return null;
    }

    private static HashMap<String, String> setServiceValues(ContextObject co) {
	HashMap<String, String> map = new HashMap<String, String>();
	Object[] svcData = (Object[]) co.getServiceTypes()[0].getDescriptors();
	if (svcData != null && svcData.length > 0) {
	    for (int i = 0; i < svcData.length; i++) {
		Object tmp = svcData[i];
		if (tmp.getClass().getSimpleName()
			.equals("ByValueMetadataImpl")) {
		    ByValueMetadataImpl kev = ((ByValueMetadataImpl) tmp);
		    if (kev.getFieldMap().size() > 0) {
			if (kev.getFieldMap().containsKey("svc.region")
				&& ((String[]) kev.getFieldMap().get(
					"svc.region"))[0] != "")
			    map.put("region", ((String[]) kev.getFieldMap()
				    .get("svc.region"))[0]);
			if (kev.getFieldMap().containsKey("svc.format")
				&& ((String[]) kev.getFieldMap().get(
					"svc.format"))[0] != "")
			    map.put("format", ((String[]) kev.getFieldMap()
				    .get("svc.format"))[0]);
			if (kev.getFieldMap().containsKey("svc.level")
				&& ((String[]) kev.getFieldMap().get(
					"svc.level"))[0] != "")
			    map.put("level",
				    ((String[]) kev.getFieldMap().get(
					    "svc.level"))[0]);
			if (kev.getFieldMap().containsKey("svc.rotate")
				&& ((String[]) kev.getFieldMap().get(
					"svc.rotate"))[0] != "")
			    map.put("rotate", ((String[]) kev.getFieldMap()
				    .get("svc.rotate"))[0]);
			if (kev.getFieldMap().containsKey("svc.scale")
				&& ((String[]) kev.getFieldMap().get(
					"svc.scale"))[0] != "")
			    map.put("scale",
				    ((String[]) kev.getFieldMap().get(
					    "svc.scale"))[0]);
			if (kev.getFieldMap().containsKey("svc.clayer")
				&& ((String[]) kev.getFieldMap().get(
					"svc.clayer"))[0] != "")
			    map.put("clayer", ((String[]) kev.getFieldMap()
				    .get("svc.clayer"))[0]);
		    }
		}
	    }
	}
	return map;
    }
}
