public class TwitterClientCredentialsAuth extends Auth.AuthProviderPluginClass {
    
    // Name for this auth provider.
    private String authProvider = 'Twitter'; 
    
    // Api name for the custom metadata type created for this auth provider.
    private String customMetadataTypeApiName = 'TwitterAuth__mdt'; 
    
    // Name for the generic username displayed in the named credential configuration.
    private String userName = 'Anonymous User'; 
    
    // Type of token.
    private String tokenType = 'secret';
    
    // Structure of a token response from Twitter
    public class TwitterResponse {
        public String token_type;
        public String access_token;
    }
    
    //name of custom metadata type to embed configuration fields in auth provider
    public String getCustomMetadataType() {
        return customMetadataTypeApiName;
    } 
    
    //directly redirect the user back to the callback URL, as we already have the client key and secret  
    //to be used for authenticating directly
    public PageReference initiate(Map<string,string> authProviderConfiguration, String stateToPropagate) {
        return new PageReference(authProviderConfiguration.get('Callback__c') +'?state=' +stateToPropagate); 
    } 
    
    //handle instantaneous callback and then use named credetial (username and password / client key and secret) to retrieve access token
    public Auth.AuthProviderTokenResponse handleCallback(Map<string,string> authProviderConfiguration, Auth.AuthProviderCallbackState state ) {
        return new Auth.AuthProviderTokenResponse(authProvider, retriveToken(authProviderConfiguration.get('NamedCredential__c')), tokenType, state.queryParameters.get('state'));
    } 
    
    //if access token expired, reuse named credetial 4to retrieve access token
    public override Auth.OAuthRefreshResult refresh(Map<String,String> authProviderConfiguration, String refreshToken) {
        return new Auth.OAuthRefreshResult(retriveToken(authProviderConfiguration.get('NamedCredential__c')), tokenType);
    }
    
    //return fake username, as client_credential auth is not tied to a specific user
    public Auth.UserData getUserInfo(Map<string,string> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        return new Auth.UserData(null, null, null, null, null, null, userName, null, authProvider, null, new Map<String,String>()); 
    }
    
    //make HTTP call to token endpoint using client credentials to retrieve access token
    private String retriveToken(String namedCredential) {
        
        HttpRequest req = new HttpRequest();
        
        req.setEndpoint('callout:'+namedCredential); 
        req.setHeader('Content-Type','application/x-www-form-urlencoded;charset=UTF-8'); 
        req.setMethod('POST'); 
        req.setBody('grant_type=client_credentials');
        
        HTTPResponse res = new Http().send(req); 
        
        return deserialiseToken(res);
    }
    
    //deserialise response and return token
    private String deserialiseToken(HTTPResponse res) {
        
        String responseBody = res.getBody();
        
        TwitterResponse parsedResponse = (TwitterResponse) System.JSON.deserialize(responseBody, TwitterResponse.class);
        
        return parsedResponse.access_token;
    }
}