package com.pamtech.entitlement.service.pip;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.entitlement.pip.AbstractPIPAttributeFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import javax.net.ssl.SSLContext;

/**
 * This is sample custom attribute finder class for WSO2 Identity Server. To register this class as attribute finder,
 * following configs should be added in the deployment.toml file of the server.
 * <p>
 * [identity.entitlement.policy_point.pip]
 * attribute_designators = [
 *      "org.wso2.carbon.identity.entitlement.pip.DefaultAttributeFinder",
 *      "org.wso2.carbon.identity.application.authz.xacml.pip.AuthenticationContextAttributePIP",
 *      "com.pamtech.entitlement.service.pip.SampleAttributeFinder"
 * ]
 */
public class SampleAttributeFinder extends AbstractPIPAttributeFinder {

    private static final ServerConfiguration config = ServerConfiguration.getInstance();
    private static Log log = LogFactory.getLog(SampleAttributeFinder.class);
    private static String TRUST_STORE_LOCATION = config.getFirstProperty("Security.TrustStore.Location");
    private static String TRUST_STORE_PASSWORD = config.getFirstProperty("Security.TrustStore.Password");
    private static final String USER_PERMISSION_CLAIM_URI = "https://pamtech.com/claims/permission";
    private String externalServiceUrl = null;

    /**
     * The required properties should be defined against the registered module in the deployment.toml. This method
     * reads the properties and initiate the module.
     *  [[identity.entitlement.extension]]
     *  name="com.pamtech.entitlement.service.pip.SampleAttributeFinder"
     *  [identity.entitlement.extension.properties]
     *  ExternalServiceUrl = "http://pamtech.free.beeceptor.com"
     *
     */
    public void init(Properties properties) throws Exception {

        // "ExternalServiceUrl" is read from the deployment.toml file as a property defined for this custom attribute
        // finder.
        externalServiceUrl = (String) properties.get("ExternalServiceUrl");

        if (StringUtils.isBlank(externalServiceUrl)) {
            throw new Exception("External service URL can not be null. Please configure it in the " +
                    "entitlement.properties file.");
        }

        if (log.isDebugEnabled()) {
            log.debug("SampleAttributeFinder is initialized successfully. \b External Service URL is set to '" +
                    externalServiceUrl + "'.");
        }
    }

    public Set<String> getAttributeValues(String subjectId, String resourceId, String actionId,
                                          String environmentId, String attributeId, String issuer) throws
            Exception {

        Set<String> values = new HashSet<>();

        if (log.isDebugEnabled()) {
            log.debug("Retrieving attribute values of subjectId \'" + subjectId + "\' with attributeId \'" +
                    attributeId + "\'");
        }

        if (StringUtils.isEmpty(subjectId)) {
            if (log.isDebugEnabled()) {
                log.debug("subjectId value is null or empty. Returning empty attribute set");
            }
            return values;
        }

        // Execute this logic when the attribute "https://pamtech.com/claims/permission" is evaluated in the XACML
        // policy. This logic depends on the customization that you need to achieve.
        if (USER_PERMISSION_CLAIM_URI.equals(attributeId)) {
            JSONObject permissionObject = getUserProfile(subjectId);
            if (permissionObject != null && permissionObject.has("permissions")) {
                JSONArray permissions = permissionObject.getJSONArray("permissions");
                if (permissions != null) {
                    for (int i = 0; i < permissions.length(); i++) {
                        values.add(permissions.getString(i));
                    }
                }
            }
        }

        return values;

    }

    @Override
    public String getModuleName() {

        return "Sample Attribute Finder";
    }

    @Override
    public Set<String> getSupportedAttributes() {

        Set<String> supportedAttrs = new HashSet<String>();
        supportedAttrs.add(USER_PERMISSION_CLAIM_URI);
        return supportedAttrs;
    }

    /**
     * This method will call the external service and get the required attributes.
     *
     * @param userId user id that is coming in the request.
     * @return user's permission
     * @throws Exception if the user profile cannot be successfully retrieved.
     */
    private JSONObject getUserProfile(String userId) throws Exception {

        String userPermissionsUrl = externalServiceUrl + "/" + userId + "/permissions";

        try (CloseableHttpClient httpclient = getHttpsClient()) {

            HttpGet httpGet = new HttpGet(userPermissionsUrl);

            try (CloseableHttpResponse response = httpclient.execute(httpGet)) {

                if (log.isDebugEnabled()) {
                    log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " when invoking GET for URL: "
                            + externalServiceUrl);
                }
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            response.getEntity().getContent()));
                    String inputLine;
                    StringBuilder responseString = new StringBuilder();

                    while ((inputLine = reader.readLine()) != null) {
                        responseString.append(inputLine);
                    }
                    return new JSONObject(responseString.toString());
                } else {
                    throw new Exception("Error while retrieving data from " + externalServiceUrl + ". Found http " +
                            "status " + response.getStatusLine());
                }
            } finally {
                httpGet.releaseConnection();
            }
        }
    }

    private CloseableHttpClient getHttpsClient() throws Exception {

        SSLContext sslcontext = getSSLContext();
        SSLConnectionSocketFactory factory = new SSLConnectionSocketFactory(sslcontext, SSLConnectionSocketFactory
                .BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
        return HttpClients.custom().setSSLSocketFactory(factory).build();

    }

    private SSLContext getSSLContext() throws IOException, KeyStoreException, CertificateException,
            NoSuchAlgorithmException, KeyManagementException {

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream inStream = new FileInputStream(new File(TRUST_STORE_LOCATION))) {
            trustStore.load(inStream, TRUST_STORE_PASSWORD.toCharArray());
        }
        return SSLContexts.custom().loadTrustMaterial(trustStore).build();
    }
}
