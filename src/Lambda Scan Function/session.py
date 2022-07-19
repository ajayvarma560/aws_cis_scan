from os import access
import boto3

# The calls to AWS STS AssumeRole must be signed with the access key ID
# and secret access key of an existing IAM user or by using existing temporary 
# credentials such as those from another role. (You cannot call AssumeRole 
# with the access key for the root account.) The credentials can be in 
# environment variables or in a configuration file and will be discovered 
# automatically by the boto3.client() function. For more information, see the 
# Python SDK documentation: 
# http://boto3.readthedocs.io/en/latest/reference/services/sts.html#client

def get_boto3_session(requestId,access_type,access_input,Duration=3600):

    if access_type.lower() == "crossaccount":

        # create an STS client object that represents a live connection to the 
        # STS service

        sts_client = boto3.client('sts')

        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name.
        try:

            assumed_role_object=sts_client.assume_role(
                RoleArn=access_input['arn'],
                RoleSessionName="AssumeRoleSession" + str(requestId),
                ExternalId = "AxiomIO8bea4a6849a7432855bb04f8bb1ca752",
                DurationSeconds=Duration
            )
        
        # From the response that contains the assumed role, get the temporary 
        # credentials that can be used to make subsequent API calls
        
            credentials=assumed_role_object['Credentials']
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
             # checks if given creds are valid or not if valid provides output else raises exception

            session_client = session.client('sts')
            res = session_client.get_caller_identity()

            return session
        
        except Exception as e:
            print("Exception in user input @ CrossAccount : ",str(e))
            return{
             'error': "Error in User Input."   
            }

    elif access_type.lower() == "credentials":
        try:
            if access_input['access_key'] == "" or access_input['access_secret'] == "":
                return{
             'error': "Error in User Input."   
            }
            session = boto3.Session(
                aws_access_key_id=access_input['access_key'],
                aws_secret_access_key=access_input['access_secret']
            )

             # checks if given creds are valid or not if valid provides output else raises exception
            
            session_client = session.client('sts')
            res = session_client.get_caller_identity()

            return session

        except Exception as e:
            print("Exception in user input @ Credentials : ",str(e))
            return{
             'error': "Error in User Input."   
            }
    else:
        print("Exception in Reading Input")
        return{
             'error': "Unknown Input."   
            }

#input method 1
# access_input = {
#             'access_key' : "some value",
#             'access_secret' : "some value",
#              }
# access_type = 'credentials'

#input method 2
# access_input = {'arn':'arn_value'}
# access_type = 'cross_account'

# session = get_boto3_session("random_id",access_type,access_input)