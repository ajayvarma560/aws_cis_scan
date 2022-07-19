import boto3
from boto3.dynamodb.conditions import Key
import uuid
import json
import base64
import session
import os


AWS_CIS_BENCHMARK_VERSION = "1.3"
version = "1.3"
heading = "AWS CIS Benchmarks"

def get_aws_account_number(boto3_session):
    client = boto3_session.client("sts")
    account_number = client.get_caller_identity()["Account"]
    return account_number

def check_permissions(session,access_type,access_input):

        try:
                client = session.client('iam')
                if access_type.lower() == "crossaccount":
                        # res= client.list_roles()
                        paginator = client.get_paginator('list_roles')
                        for j in paginator.paginate():
                                for i in j['Roles']:
                                        if i['Arn'] == access_input['arn']:
                                                role=i['RoleName']
                        attpol = client.list_attached_role_policies(RoleName=role)
                        for i in  attpol['AttachedPolicies']:
                                if i['PolicyName']=='ReadOnlyAccess' and i['PolicyArn'] == 'arn:aws:iam::aws:policy/ReadOnlyAccess':
                                        return True

                elif access_type.lower() == "credentials":
                        res= client.get_user()
                        user= res['User']['UserName']
                        attpol = client.list_attached_user_policies(UserName=user)
                        for i in  attpol['AttachedPolicies']:
                                if i['PolicyName']=='ReadOnlyAccess' and i['PolicyArn'] == 'arn:aws:iam::aws:policy/ReadOnlyAccess':
                                        return True
                return False
        except Exception as e:
            print("Exception in permissions : ",str(e))
            return False
        

def check_access(requestId,input):

        # Checks if the provided creds are valid or not
        session = session.get_boto3_session(requestId,input['access_type'],input['access_input'],900)
        if "error" in str(session):
                return False
        else:
                if (check_permissions(session,input['access_type'],input['access_input'])) == True:
                        return True
                else:
                        return False   

def aws_cis_scan_request_handler(event, context):


        lam = boto3.client('lambda')
        cis_scan_function = os.environ['CIS_Scan_LambdaFunction']
        try:
                    try:    
                        accounts = 0 
                        user_input = []
                        reqid = event['body']['requestId']                        
                        if len(event['body']['scan_input'])==1:
                                accounts = 1
                        if accounts == 0:
                                return{
                                        'error': 'Invalid Input'
                                }
                        for user_creds in event['body']['scan_input']:
                                if check_access(reqid,user_creds) != False:
                                        user_input.append(user_creds)
                                else:
                                        return{
                                                        'error': 'Invalid Keys/ARN provided' 
                                                }

                        for input in user_input :
                                if 'access_type' in input and 'access_input' in input:                                   
                                        if input['access_type'].lower() != "credentials" and input['access_type'].lower() !="crossaccount":
                                                return{
                                                        'error': 'Unknown Access Type' 
                                                }
                                        else:  
                                                lambda_input={
                                                "access_type": input['access_type'],
                                                "access_input":input['access_input'],
                                                "requestId" : reqid,
                                                "email":event['body']['email']
                                                }
                                                invoked = lam.invoke(FunctionName=cis_scan_function,InvocationType='Event',Payload=json.dumps(lambda_input))
                        return {  
                                "requestId":reqid,
                                "status": "INPROGRESS"
                        }
                    except Exception as e:
                            print("Exception in aws scan request ", str(e))
                            return{
                                    'error': 'Invalid Request Parameters'
                            }
        except Exception as e:
                print("Exception in aws scan request : ",str(e))
                return {
                                'error': 'Invalid Request Parameters'
                }
if __name__ == '__main__':

#input method 1
# access_input = {
#             'access_key' : "some value",
#             'access_secret' : "some value",
#              }
# access_type = 'credentials'

#input method 2
# access_input = {'arn':'arn_value'}
# access_type = 'cross_account'

        event =  {
    "body": {
    "requestId": "<value>",
    "scan_input": [
      {
        "access_type": "<value>",
        "access_input": {
          "arn": "<value>"
        }
      }
    ],
    "email": "<value>"
  }
}
        aws_cis_scan_request_handler(event, "context")
