package org.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.*;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.utils.IpAddressMatcher;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

public class ConveyLawOtpFormAuthenticator extends OTPFormAuthenticator {

    private static final Logger logger = Logger.getLogger(ConveyLawOtpFormAuthenticator.class);

    private final static Pattern ipPattern = Pattern.compile("((^\\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\\s*$)|(^\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?\\s*$))");

    public static final String TRUSTED_NETWORKS = "trustedNetworks";

    public static final String ENABLED_ROLE = "enabledRole";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        logger.debug("Calling authenticate on ConveyLawOtpFormAuthenticator");

        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        MultivaluedMap<String, String> headers = context.getHttpRequest().getHttpHeaders().getRequestHeaders();

        for (Map.Entry<String, String> configEntry : config.entrySet()) {
            logger.debug(String.format("Found config value: %s: %s", configEntry.getKey(), configEntry.getValue()));
        }

        for (Map.Entry<String, List<String>> headerEntry : headers.entrySet()) {
            for (String headerValue : headerEntry.getValue()) {
                logger.debug(String.format("Found header value: %s: %s", headerEntry.getKey(), headerValue));
            }
        }

        if (isTrustedNetwork(config.get(TRUSTED_NETWORKS), headers)) {
            logger.debug("User is from a trusted network");
            context.success();
            return;
        } else {
            logger.debug("User is from an untrusted network");
        }

        if (isEnabledUser(context.getRealm(), context.getUser(), config.get(ENABLED_ROLE))) {
            logger.debug("User is in a remote enabled role");
            super.authenticate(context);
            return;
        } else {
            logger.debug("User is not in a remote enabled role");
        }

        //context.cancelLogin();
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS);
    }

    private boolean isTrustedNetwork(String trustedNetworks, MultivaluedMap<String, String> requestHeaders) {
        if ((trustedNetworks != null) && (trustedNetworks.length() > 0)) {
            for (Map.Entry<String, List<String>> headerEntries : requestHeaders.entrySet()) {
                if (("X-Forwarded-For".equalsIgnoreCase(headerEntries.getKey()))
                        || ("X-Forwarded-Host".equalsIgnoreCase(headerEntries.getKey()))) {
                    for (String headerValue : headerEntries.getValue()) {
                        headerValue = headerValue != null ? headerValue.trim() : headerValue;
                        if ((headerValue != null) && (ipPattern.matcher(headerValue).matches())) {
                            return (isMatchedNetwork(trustedNetworks, headerValue));
                        }
                    }
                }
            }
            logger.warn("Could not ascertain the client's IP address and so I am defaulting to it being an untrusted network.");
            return false;
        }
        logger.info("No trusted networks defined");
        return false;
    }

    private boolean isMatchedNetwork(String trustedNetworks, String ipAddress) {
        String[] trustedNetworksArray = ((trustedNetworks != null) && (trustedNetworks.length() > 0)) ? trustedNetworks.split(",") : new String[]{};
        for (String trustedNetwork : trustedNetworksArray) {
            IpAddressMatcher iam = ((trustedNetwork != null) && (trustedNetwork.length() > 0)) ? new IpAddressMatcher(trustedNetwork.trim()) : null;
            if ((iam != null) && (iam.matches(ipAddress))) {
                return true;
            }
        }
        return false;
    }

    private boolean isEnabledUser(RealmModel realm, UserModel user, String roleName) {
        logger.debug(String.format("Testing if User: %s has Role: %s", user.getUsername(), roleName));
        for (RoleModel role : user.getRoleMappings()) {
            logger.debug(String.format("Has Role: %s", role.getName()));
        }
        RoleModel enabledRole = getRoleFromString(realm, roleName);
        logger.debug(String.format("Testing to see if is in role: %s", enabledRole != null ? enabledRole.getName() : "Role Not Found"));
        return roleName != null && RoleUtils.hasRole(user.getRoleMappings(), enabledRole);
    }

    private boolean isOTPRequired(KeycloakSession session, RealmModel realm, UserModel user) {
        for (AuthenticatorConfigModel configModel : realm.getAuthenticatorConfigs()) {
            Map<String, String> config = configModel.getConfig();
            if ((config.containsKey(ENABLED_ROLE))
                    && (isEnabledUser(realm, user, config.get(ENABLED_ROLE)))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("Calling setRequiredActions on ConveyLawOtpFormAuthenticator");
        if (!isOTPRequired(session, realm, user)) {
            user.removeRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        } else if (!user.getRequiredActions().contains(UserModel.RequiredAction.CONFIGURE_TOTP.name())) {
            user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP.name());
        }
    }
}
