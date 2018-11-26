package org.keycloak.authentication.authenticators.browser;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static java.util.Arrays.asList;
import static org.keycloak.authentication.authenticators.browser.ConveyLawOtpFormAuthenticator.ENABLED_ROLE;
import static org.keycloak.authentication.authenticators.browser.ConveyLawOtpFormAuthenticator.TRUSTED_NETWORKS;
import static org.keycloak.provider.ProviderConfigProperty.ROLE_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class ConveyLawOtpFormAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-conveylaw-otp-form";

    public static final ConveyLawOtpFormAuthenticator SINGLETON = new ConveyLawOtpFormAuthenticator();

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.OPTIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        //NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        //NOOP
    }

    @Override
    public void close() {
        //NOOP
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.TOTP;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }


    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Convey Law OTP Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a OTP on a separate OTP form. Only shown if required based on the configured conditions.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {

        ProviderConfigProperty trustedNetworks = new ProviderConfigProperty();
        trustedNetworks.setType(STRING_TYPE);
        trustedNetworks.setName(TRUSTED_NETWORKS);
        trustedNetworks.setLabel("Trusted Networks");
        trustedNetworks.setHelpText("OTP is always skipped if user is authenticating from a trusted network, comma separated address ranges in the form 1.2.3.4/24.");

        ProviderConfigProperty enabledRole = new ProviderConfigProperty();
        enabledRole.setType(ROLE_TYPE);
        enabledRole.setName(ENABLED_ROLE);
        enabledRole.setLabel("External Login Role");
        enabledRole.setHelpText("Allow login with OTP from users in this role from untrusted networks");

        return asList(trustedNetworks, enabledRole);
    }
}
