#Script to restore and validate an RDS database backup copy
#It's run as a Lambda function and triggered by EventBridge rules for AWS Backup events
#It's imported into Lambda as a .zip file that also includes the pymysql package dependency
#It uses the Python 3.9 runtime, with VPC access enabled, 128MB memory and 60s timeout
#The target VPC must route to the internet via a NAT Gateway or VPC endpoints
#Lambda and RDS security groups must allow access from the lamda function to the restored instance
#The following execution permissions are required:
#   - managed policy: AWSLambdaBasicExecutionRole 
#   - managed policy: AWSLambdaVPCAccessExecutionRole
#   - managed policy: AWSBackupOperatorAccess 
#   - inline policy: secretsmanager:GetSecretValue (for secret in env var)
#   - inline policy: rds:ModifyDBInstance, rds:deleteDBInstance
#   - inline policy: s3:PutObject (for bucket in env var)
#   - inline policy: logs:PutLogEvents and logs:DescribeLogStreams (for log group in env var) 

import os
import sys
import traceback
import json
import boto3
import logging
import pymysql
import time
import datetime
from botocore.exceptions import ClientError

#Initialise boto clients for AWS Backup, RDS, S3 and CloudWatch Logs
backup = boto3.client('backup')
rds = boto3.client('rds')
s3 = boto3.client('s3')
logs = boto3.client('logs')

#RDS settings
rds_restore_port = os.environ['RDS_RESTORE_PORT']
rds_restore_dbsubnet_group = os.environ['RDS_RESTORE_DBSUBNET_GROUP']
rds_restore_security_group = os.environ['RDS_RESTORE_SECURITY_GROUP']
rds_secret_name = os.environ['RDS_SECRET_NAME']

#Role for AWS Backup to use for restore
restore_iam_role_arn = os.environ['RESTORE_IAM_ROLE_ARN'] 

#S3 bucket for restore and validation results
s3_bucket = os.environ['S3_OUTPUT_BUCKET']

#CW log group and stream for restore and validation results
log_group = os.environ['CW_RESULTS_LOG_GROUP']
log_stream = os.environ['CW_RESULTS_LOG_STREAM']

#MySQL connection
conn = None

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#Entry point
def lambda_handler(event, context):

    #Determine and log job type based on event - copy completed vs restore completed
    job_type = event['detail-type'].split(' ')[0]
    logger.info('Trigger: ' + job_type + ' job completed')

    try:
        if job_type == 'Copy':
            handle_backup_copy(event)
        elif job_type == 'Restore':
            handle_restore(event)

    except Exception as e:
        logger.error(str(e))
        logger.info(traceback.format_exc())
        raise 
    
    return

#Restore the backup that's just completed
def handle_backup_copy(input_event):
    
    #Get backup job ID from incoming event
    copy_job_id = input_event['detail']['copyJobId']
    logger.info('Copy job ID: ' + copy_job_id)

    backup_vault_name = input_event['detail']['destinationBackupVaultArn'].split(':')[6]
    recovery_point_arn = input_event['detail']['destinationRecoveryPointArn']
    logger.info('Backup vault name: ' + backup_vault_name)
    logger.info('Recovery point ARN: ' + recovery_point_arn)

    #Get recovery point restore metadata
    metadata = backup.get_recovery_point_restore_metadata(
        BackupVaultName=backup_vault_name,
        RecoveryPointArn=recovery_point_arn
    )

    #Generate a unique valid new RDS instance name
    new_instance_name = (metadata['RestoreMetadata']['DBInstanceIdentifier'])[0:20] + '-' + copy_job_id[0:40]
    if new_instance_name[-1] == '-':
        new_instance_name = new_instance_name[:-1] + 'z'
    
    #Add metadata (can also add AZ, parameter group and option group to override those copied from the source)    
    metadata['RestoreMetadata']['DBInstanceIdentifier'] = new_instance_name
    metadata['RestoreMetadata']['Port'] = rds_restore_port
    metadata['RestoreMetadata']['DBName'] = ''
    metadata['RestoreMetadata']['DBSubnetGroupName'] = rds_restore_dbsubnet_group
    metadata['RestoreMetadata']['VpcSecurityGroupIds'] = '[\"' + rds_restore_security_group + '\" ]'

    #Start restore job
    logger.info('Starting the restore job')
    restore_request = backup.start_restore_job(
            RecoveryPointArn=recovery_point_arn,
            IamRoleArn=restore_iam_role_arn,
            Metadata=metadata['RestoreMetadata']
    )

    #logger.info('Restore request: ' + json.dumps(restore_request))
    
    return

#Validate the restore that's just completed
def handle_restore(input_event):
    
    #Get restore job ID from incoming event
    restore_job_id = input_event['detail']['restoreJobId']
    logger.info('Restore job ID: ' + restore_job_id)
    
    #Get restore job details
    restore_info = backup.describe_restore_job(
                    RestoreJobId=restore_job_id
    )

    logger.info('Restore from the backup was successful')

    #Retrieve instance ID for the new instance from restore job details
    db_instance = input_event['detail']['createdResourceArn'].split(':')[6]
    logger.info('Restored instance: ' + db_instance)

    instance_info = rds.describe_db_instances(
                DBInstanceIdentifier=db_instance
    )
    
    rds_host = instance_info['DBInstances'][0]['Endpoint']['Address']
    rds_port = instance_info['DBInstances'][0]['Endpoint']['Port']
    logger.info('Restored endpoint and port: ' + rds_host + ', ' + str(rds_port))

    logger.info('Validating data recovery before deletion')
    age_latest_db_tx = validate_db_data(rds_host, rds_port)
    
    logger.info('Restore from ' + restore_info['RecoveryPointArn'] + ' was successful; database is accessible with age of latest db tx = ' + str(age_latest_db_tx)) 
    
    creation_obj = datetime.datetime.strptime(input_event['detail']['creationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
    completion_obj = datetime.datetime.strptime(input_event['detail']['completionDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
    restore_elapsed = (completion_obj - creation_obj).total_seconds() / 60.0

    #Create output summary (timestamps modified to be compatible with Athena timestamp format)
    restore_summary = {
        "recovery_point_arn" : restore_info['RecoveryPointArn'],
        "restored_instance_id" : db_instance,
        "restore_start_time" : (input_event['detail']['creationDate']).replace('T', ' ').replace('Z', ''),
        "restore_end_time" : (input_event['detail']['completionDate']).replace('T', ' ').replace('Z', ''),
        "restore_duration" : round(restore_elapsed),
        "age_latest_db_tx" : round(age_latest_db_tx)
    }
    
    #Write to S3. e.g. for querying from Athena
    restore_string_data = json.dumps(restore_summary)
    logger.info('Results summary: ' + restore_string_data)
    
    now = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")

    s3.put_object(
        Body=restore_string_data, 
        Bucket=s3_bucket, 
        Key=db_instance + '-' + now + '.json'
    )
    
    #Write to CloudWatch Logs, e.g. for querying from CloudWatch Logs Insights
    log_event = {
        'logGroupName': log_group,
        'logStreamName': log_stream,
        'logEvents': [
            {
                'timestamp': round(time.time() * 1000),
                'message':  restore_string_data
            }
        ]
    }
    
    response = logs.describe_log_streams(
                logGroupName=log_group
    )
    
    if 'uploadSequenceToken' in response['logStreams'][0]:
       log_event.update({'sequenceToken' : response['logStreams'][0]['uploadSequenceToken']})
   
    response = logs.put_log_events(**log_event)
    #logger.info('Put log response: ' + json.dumps(response))

    #Delete restored instance
    logger.info('Deleting restored instance: ' + db_instance)
    rds.delete_db_instance(
                DBInstanceIdentifier=db_instance,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True
    )
    
    return

#Validate representative data in the restored database
def validate_db_data(rds_host, rds_port):

    global conn
    age_latest_db_tx = -1
    
    open_db_connection(rds_host, rds_port)

    cur = conn.cursor()
    row_count = cur.execute('select ROUND(TIME_TO_SEC(TIMEDIFF(CURRENT_TIMESTAMP(), max(EventTime))) / 60, 0) from test.Transactions')

    if row_count == 1:
        row = cur.fetchone()
        age_latest_db_tx = row[0]
    else:
        logger.error('ERROR: validate_db_data(): No age for latest db tx calculated')
        
    cur.close()
    conn.close()

    return age_latest_db_tx

#Open MySQL database using a login from Secrets Manager
def open_db_connection(rds_host, rds_port):

        global conn
        name = "None"
        password = "None"
        
        # Create a Secrets Manager client
        session = boto3.session.Session()
        region_name = session.region_name

        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
        
        # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        # We rethrow the exception by default.
        
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=rds_secret_name
            )
            #print(get_secret_value_response)
        except ClientError as e:
            logger.error("ERROR: open_db_connection(): Could not retrieve Secrets Manager secret")
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
        else:
            # Decrypts secret using the associated KMS CMK.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
                j = json.loads(secret)
                name = j['username']
                password = j['password']
            else:
                decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
                name = decoded_binary_secret.username
                password = decoded_binary_secret.password    
        
        try:
            if(conn is None):
                conn = pymysql.connect(
                    host=rds_host, port=rds_port, user=name, passwd=password, connect_timeout=30)
            elif (not conn.open):
                conn = pymysql.connect(
                    host=rds_host, port=rds_port, user=name, passwd=password, connect_timeout=30)
    
        except Exception as e:
            logger.error("ERROR: open_db_connection(): Could not connect to MySql instance")
            raise e
            
        return
