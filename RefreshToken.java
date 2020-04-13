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


public class RefreshToken {

    private static String clientId = "xxxxxxxxxxxxxxxxxxxxxxxxxx";
    private static String userPoolId = "ap-south-1_xxxxxx";

    private static String userName = "xxxxxx";
    private static String userPassword = "xxxxxx";
    private static String newuserPassword = "xxxxx";



    public static void main(String args[]) {

        String idToken = getIdToken();
        System.out.println("idToken : " + idToken);
        //getAWSCreds(idToken);
    }

    public static String getIdToken() {

        System.setProperty("aws.accessKeyId", "xxxxxx");
        System.setProperty("aws.secretKey", "xxxxxxxx");

        AWSCognitoIdentityProvider provider = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(Regions.AP_SOUTH_1).withCredentials(new SystemPropertiesCredentialsProvider()).build();
        Map<String, String> authParams = new HashMap<>();
        System.out.println("Provider========>"+provider);

        authParams.put("USERNAME", userName);
        authParams.put("PASSWORD", newuserPassword);
        authParams.put("REFRESH_TOKEN", "xxxxxxxxxxxxxx");

        AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest().withClientId(clientId)
                .withUserPoolId(userPoolId).withAuthFlow(AuthFlowType.REFRESH_TOKEN_AUTH).withAuthParameters(authParams);

        System.out.println("adminInitiateAuthRequest========>"+adminInitiateAuthRequest);
        AdminInitiateAuthResult result = provider.adminInitiateAuth(adminInitiateAuthRequest);


        System.out.println("result.getChallengeName() : =======>" + result);

        if (StringUtils.isNullOrEmpty(result.getChallengeName())) {
            return "ID token is ====>"+
                    result.getAuthenticationResult().getIdToken() +"\n"+
                    "Refresh token is ====>"+result.getAuthenticationResult().getRefreshToken();
        }

        else {
            //resetPassword(userName, newuserPassword, result, provider);
            return "abc";
        }





}

}