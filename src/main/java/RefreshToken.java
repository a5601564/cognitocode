import java.util.HashMap;
import java.util.Map;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClientBuilder;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityRequest;
import com.amazonaws.services.cognitoidentity.model.GetCredentialsForIdentityResult;
import com.amazonaws.services.cognitoidentity.model.GetIdRequest;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.iot.AWSIot;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.AWSIotClientBuilder;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.util.StringUtils;

/**
 *
 * @author Mayur
 The id token is valid for 60 minutes, post which either the user has to pass the username and password again or the other option is user can pass the username and refresh token.
 Refresh token can be valid for 3650 days as well
 *
 */
public class RefreshToken {

    private static String clientId = "4j1p4a0i9b8htf1bd27vfn81ci"; //Replace your Cognito cliendId
    private static String userPoolId = "us-east-2_9AvY8xWN5"; //Replace your userPoolId

    private static String userName = "a5601564"; //Cognito username
    private static String userPassword = "5601564a"; // Cognito password
    private static String newuserPassword = "5601564aA"; // Cognito newpassword for reset password


    public static void main(String args[]) {

        String idToken = getIdToken();
        System.out.println("idToken : " + idToken);
        //getAWSCreds(idToken);
    }

    public static String getIdToken() {

        System.setProperty("aws.accessKeyId", "AKIAJVVIFAURUT7GA66A");
        System.setProperty("aws.secretKey", "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");

        AWSCognitoIdentityProvider provider = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(Regions.AP_SOUTH_1).withCredentials(new SystemPropertiesCredentialsProvider()).build();
        Map<String, String> authParams = new HashMap<>();
        System.out.println("Provider========>" + provider);

        authParams.put("USERNAME", userName);
        authParams.put("PASSWORD", newuserPassword);
        authParams.put("REFRESH_TOKEN", "xxxxxxxxxxxxxx");

        AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest().withClientId(clientId)
                .withUserPoolId(userPoolId).withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH).withAuthParameters(authParams);

        System.out.println("adminInitiateAuthRequest========>" + adminInitiateAuthRequest);
        AdminInitiateAuthResult result = provider.adminInitiateAuth(adminInitiateAuthRequest);


        System.out.println("result.getChallengeName() : =======>" + result);

        if (StringUtils.isNullOrEmpty(result.getChallengeName())) {
            return "ID token is ====>" +
                    result.getAuthenticationResult().getIdToken() + "\n" +
                    "Refresh token is ====>" + result.getAuthenticationResult().getRefreshToken();
        } else {
            //resetPassword(userName, newuserPassword, result, provider);
            return "abc";
        }
    }
}