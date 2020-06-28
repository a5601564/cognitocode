# cognitocode
For the usecase where one application wants to securely invoke API of other application (B2B) Cognito can be used for authentication by integrating AWS API Gateway with Cognito authorizer.
Cognito has three tokens id token, access token and refresh token
In API Gateway, relying application can pass the Cognito id token for authentication
There are two options to generate the Cognito id token
* a. Using Java code (CognitoUtils and RefreshToken) using AWS SDK
* b. Lambda code
## Getting Started
* For option a you can use any editor and compile and run the Java code


* For option b need to create a lambda function in your AWS account
### Prerequisites
* aws-java-sdk version 1.11.631
* IAM user access key and secret key with permissions for AmazonCognitoPowerUser
* Create Cognito User pool
