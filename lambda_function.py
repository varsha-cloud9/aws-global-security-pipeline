import json
import boto3
import urllib.parse
import os

# Connect to AWS structural frameworks across regions
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

# MULTI-REGION CONFIGURATION
PRIMARY_LANDING = "untrusted-landing-primary-pc-11"
SECONDARY_BACKUP = "dr-backup-vault-secondary-pc-11"
QUARANTINE_ZONE = "quarantine-zone-primary-pc-11"
FORBIDDEN_EXTENSIONS = ['.exe', '.sh', '.bat', '.scr']

def lambda_handler(event, context):
    for record in event['Records']:
        source_bucket = record['s3']['bucket']['name']
        file_key = urllib.parse.unquote_plus(record['s3']['object']['key'], encoding='utf-8')

        print(f"Global Trigger! Scanning file: {file_key} intercepted from: {source_bucket}")

        # Check for forbidden extensions
        file_extension = '.' + file_key.split('.')[-1].lower() if '.' in file_key else ''

        if file_extension in FORBIDDEN_EXTENSIONS:
            print(f"🚨 SECURITY BREACH DETECTED: Malicious extension {file_extension} found!")

            # 1. QUARANTINE THE THREAT
            try:
                s3_client.copy_object(
                    Bucket=QUARANTINE_ZONE,
                    CopySource={'Bucket': source_bucket, 'Key': file_key},
                    Key=file_key
                )
                print(f"Isolated file in primary quarantine zone: {QUARANTINE_ZONE}")
            except Exception as e:
                print(f"⚠️ Quarantine failed: {str(e)} - Continuing with purge and alert.")

            # 2. PURGE THE THREAT FROM BOTH GEOGRAPHICAL REGIONS
            # Remove from N. Virginia Primary landing bucket
            try:
                s3_client.delete_object(Bucket=PRIMARY_LANDING, Key=file_key)
                print("Successfully purged file from Primary Region.")
            except Exception as e:
                print(f"Primary purge notice: {str(e)}")

            # Remove from Oregon DR Backup bucket (cross-region cleanup)
            try:
                s3_client.delete_object(Bucket=SECONDARY_BACKUP, Key=file_key)
                print("Successfully purged mirrored file from Secondary DR Region.")
            except Exception as e:
                print(f"Secondary backup purge notice: {str(e)} - (File may not have finished replicating yet)")

            # 3. DISPATCH GLOBAL ALERT NOTIFICATION
            alert_msg = f"CRITICAL DEVSECOPS ALERT\n\nA malicious payload was intercepted across your global architecture.\n\nFile: {file_key}\nStatus: Purged from Primary ({PRIMARY_LANDING}) and Secondary Backup ({SECONDARY_BACKUP}). Asset safely quarantined."
            sns_client.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Message=alert_msg,
                Subject="⚠️ Global Infrastructure Security Violation"
            )

        else:
            print(f"✅ FILE CLEAN: File {file_key} is safe. Retained in Primary and mirrored in Secondary DR storage.")

    return {"statusCode": 200, "body": json.dumps("Global sweep complete.")}