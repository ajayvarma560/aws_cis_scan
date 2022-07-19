import os
import boto3

database = boto3.resource('dynamodb')
table_name = os.environ['DB_TABLE_NAME']
table = database.Table(table_name)

def get_record(requestId):
    try:
        record = table.get_item(Key = {
                'requestId' : requestId
            })
        print(requestId, record)
        if record.get('Item'):
            return {
                'requestId' :requestId,
                'data': record.get('Item')
                }
        return {
            'requestId': requestId,
            'data': {}
        }
    except:
        return {
            'requestId': requestId,
            'data': {}
        }

def update_record(requestId):
    try:
        updated_table = table.update_item(Key={
            'requestId': requestId
        },
        UpdateExpression="set scanCompleted = :r",
        ExpressionAttributeValues={
            ':r': 'true',
        })
        print("record updated successfully", updated_table)
    except Exception as e:
        print(str(e))