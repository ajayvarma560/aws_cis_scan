# AWS CIS SCAN

The Python-based AWS CIS Scan helps to identify the AWS resources that are non-compliant with the controls specified in CIS Benchmarks version 1.3

The CIS control categories are as follows:

1. Identity and Access Management
1. Storage
1. Logging
1. Monitoring
1. Networking

## **Steps**

1. Zip all the dependencies along with the .py files and configure the environment variables and IAM permissions as specified in the AWS Lambda Functions Section and upload to AWS Lambda.

## **AWS Services Used**

1. AWS Lambda – Two lambda functions named request function and scan function are used where the request function is used to validate the credentials provided and check if the required permissions are given and upon validation invokes the scan function which performs the actual CIS scan on your AWS infrastructure and sends the report to the specified email id.
1. Amazon DynamoDB – The DynamoDB table contains information like scan status for the associated request id.
1. Amazon SES – Amazon SES is configured to send the generated reports to the user on the provided email.

## **AWS Lambda Functions**

### A. **Lambda Request Function:** 

This function performs validation on the input and invokes the “Lambda Scan Function” upon successful validation.

This function includes request.py and session.py files in the package along with the required dependencies.zip all the files and upload them to AWS lambda.

#### **IAM Role Permissions for Lambda Request Function:**

The Lambda Request Function should have permission to invoke Lambda Scan Function, assume role permissions to assume any user-provided roles, DynamoDB permissions to access tables, along with the default lambda permissions.

#### **File Info:**

1) **request.py:** The request function is used to validate the credentials provided, check if the required permissions are given to run the scan.
2) **session.py**: This function is used to create a boto3 session that is used to communicate with the AWS API calls.

The Environment variables to be configured at Lambda Request Function are as follows

|**Environment Variable Name**|**Description**|
| :-: | :-: |
|DB\_TABLE\_NAME|DynamoDB table name|



### B. **Lambda Scan Function:**

This function performs the actual CIS scan and sends the report to the user email using the configured SMTP credentials and saves the scan status to DynamoDB.

This function includes scan.py, mailer.py, db.py and session.py files in the package along with the required dependencies. zip all the files and upload them to AWS lambda.

#### **IAM Role Permissions for Lambda Scan Function:**

The Lambda Scan Function should have assume role permissions to assume any user-provided roles, DynamoDB permissions to access tables, along with the default lambda permissions.

#### **File Info:**

1) **scan.py:** The scan file has the functions that perform the actual CIS scan on your AWS infrastructure and sends the generated report to the specified email id.
2) **session.py**: This file contains the functions that create a boto3 session which is used to communicate with the AWS API calls.
3) **db.py:** This file contains the functions that perform database operations.
4) **mailer.py:** This file contains the functions that send the report to user specified email

The Environment variables to be configured at Lambda Scan Function are as follows


|**Environment Variable Name**|**Description**|
| :-: | :-: |
|DB\_TABLE\_NAME|DynamoDB table name|
|MAIL\_USERNAME|Email UserName|
|MAIL\_PASSWORD|Email Password|
|MAIL\_PORT|Email Port (for eg: 587)|
|MAIL\_SERVER|SMTP Email Server (for eg: email-smtp.us-east-1.amazonaws.com)|
|MAIL\_USE\_SSL|to use SSL for communication (value can be True/False)|
|MAIL\_USE\_TLS|to use SSL for communication (value can be True/False)|
|TEMP\_PATH|temporary path to be used by lambda (eg: /tmp/)|
|USE\_RATE\_LIMITER|False/True|
|FROM\_ADDR|Sender Email Address|

### **Input Format for Lambda Functions:**

#### 1) **Lambda Request Function Input Format:**

The Lambda Request Function can be executed by providing the required AWS credentials in either Access key, Access Secret format, or Role ARN format using the lambda event object. 

##### a. The Input format using access key and secret key:

```json
{
  "body": {
    "requestId": "unique_scan_value",
    "scan_input": [
      {
        "access_type": "credentials",
        "access_input": {
          "access_key": "<access-key>",
          "access_secret": "<access-secret>"
        }
      }
    ],
    "email": "<user-email> "
  }
}


```
##### b. The Input format using Role ARN:
```json
{
  "body": {
    "requestId": "unique_scan_value",
    "scan_input": [
      {
        "access_type": "cross-account",
        "access_input": {
          "arn": "<aws role arn>",
        }
      }
    ],
    "email": "<user-email>"
  }
}

```
Make sure the User / Role ARN has the “arn:aws:iam::aws:policy/ReadOnlyAccess” permissions attached .


#### 2) **Lambda Scan Function Input Format**

By default, the Lambda Scan Function is invoked by Lambda Request Function, but in cases where the Lambda Scan Function must be executed then the input format is as follows:

##### a. The Input format using access key and secret key:
```json
{
    "requestId": "unique_scan_value",
        "access_type": "credentials",
        "access_input": {
          "access_key": "<access-key>",
          "access_secret": "<access-secret>"
        },
    "email": "<user-email> "
  }
```


##### b. The Input format using Role ARN:
```json
{
    "requestId": "unique_scan_value",
        "access_type": "cross-account",
        "access_input": {
          "arn": "<aws role arn>"
        },
    "email": "<user-email>"
}

```
Make sure the User / Role ARN has the “arn:aws:iam::aws:policy/ReadOnlyAccess” permissions attached .

#### **Instructions to create an IAM User access key, access secret and IAM Role**
##### **For Input Type Credentials**
1.	Log in to the AWS management console and open the [AWS IAM Console ](https://console.aws.amazon.com/iamv2/home?#/home)
2.	In the left navigation pane under the Access Management section Click on “Users” and then choose “Add users”. 
3.	Fill the “User name” field with a name of your choice (e.g. AxiomIO) and select the “Access key - Programmatic access” checkbox for “Select AWS credential type” from the “Select AWS access type” section. 
4.	Click on “Next:Permissions” and on the “Set permissions” page, choose “Attach existing policies directly” . 
5.	Click on “Next: Tags” and click on “Next: Review”, after reviewing the information click on “Create user”. 
6.	On the Success screen, click on “Download.csv” to download the credentials file or click on the “Show” button to view the Secret access key. 
7.	Copy the values of the “Access key ID” and “Secret access key” fields either from the screen or from the downloaded file and paste them in the provided fields respectively. 
##### **For Input Type Cross Account**
1.	Log in to the AWS management console and open the [AWS IAM Console ](https://console.aws.amazon.com/iamv2/home?#/home)
2.	In the left navigation pane under the Access Management section Click on “Roles” and then choose “Create role”. 
3.	In the “Select trusted entity” section, Choose the “AWS account” option and select “Another AWS account” in the “An AWS account” section. Enter the below provided AWS Account ID in the “Account ID” field. 

    a.	**Account ID: \<your AWS Account ID\>**
   
4.	On the same page under options, Select the “Require external ID” check box and enter the External ID provided below in the “External ID” field. 

    a.	**External ID: \<RandomExternalId\>**
    
    b.	**Note: Make sure the “Require MFA” option is unchecked**
    
5.	Click on Next.
6.	On the “ADD Permissions” page from the “Permissions policies” section, search and select the AWS managed policy “ReadOnlyAccess” 
7.	Click on “Next” and provide a “Role name”, “Description”, and after reviewing the information click on “Create role”. 
8.	Now, in the [IAM Console](https://console.aws.amazon.com/iamv2/home?#/home) In the left navigation pane under the Access Management section Click on “Roles” and search for the role created in step 7. 
Select the role, copy the “ARN” from the summary section and paste the ARN in the field provided.


