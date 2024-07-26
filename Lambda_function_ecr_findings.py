#!/bin/python3.10
#####################################################################
# Script developed by Sheyla Leacock
#####################################################################

import boto3
import pandas as pd
from datetime import datetime
import botocore.exceptions
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Defining boto3 clients for the connection to the AWS services
ecr_client = boto3.client('ecr')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

# Defining the bucket name variable to store the findings and the ECR repository name
bucket_name = 's3-ecr-findings'
repository_name = 'ecr-test'
object_name = ''
topic_arn = 'arn:aws:sns:us-east-1:066849108148:ecr-findings-notifications'

# Defining the method to obtain the ECR registry information and getting the registryId that will be needed as a parameter for the next method.
def get_registry_id():
    try:
        registry = ecr_client.describe_registry()
        return registry.get("registryId")
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to describe registry: %s", error)
        return None

# Defining the method to list the ECR images by sending the registryId and repositoryName parameters. 
def get_list_images(registry_id, repository_name):
    try:
        response = ecr_client.list_images(
            registryId=registry_id,
            repositoryName=repository_name
        )
        image_ids = []
        # Iterate through the images to find the image tag and image digest information
        for image in response.get('imageIds', []):
            image_digest = image.get('imageDigest')
            image_tag = image.get('imageTag', 'latest')  # 'latest' como valor predeterminado si no se encuentra imageTag
            image_ids.append({
                'imageDigest': image_digest,
                'imageTag': image_tag
            })
        return image_ids
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to list images: %s", error)
        return []

# Defining the method to describe the findings of an image scan by sending the previously obtained values of the registryId, repositoryName and image id as parameters.        
def get_image_scan_findings(registry_id, repository_name, image_id):
    try:
        findings = []
        response = ecr_client.describe_image_scan_findings(
            registryId=registry_id,
            repositoryName=repository_name,
            imageId=image_id,
            maxResults=1000
        )
        findings.extend(response.get("imageScanFindings", {}).get("enhancedFindings", []))
        
        while 'nextToken' in response:
            response = ecr_client.describe_image_scan_findings(
                registryId=registry_id,
                repositoryName=repository_name,
                imageId=image_id,
                nextToken=response['nextToken'],
                maxResults=1000
            )
            findings.extend(response.get("imageScanFindings", {}).get("enhancedFindings", []))
        return findings
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to describe image scan findings: %s", error)
        return []
        
# Getting the findings details for the report
def process_findings(findings):
    processed_findings = []
    for finding in findings:
        cvss_scores = finding.get('packageVulnerabilityDetails', {}).get('cvss', [])
        base_score = cvss_scores[0].get('baseScore') if cvss_scores else None
        processed_findings.append({
            "Finding ARN": finding.get('findingArn'),
            "Description": finding.get('description'),
            "Severity": finding.get('severity'),
            "CVSS Base Score": base_score
        })
    return processed_findings
    
# Using pandas library method json_normalize to normalize the JSON list of findings into a table and saving the normalized data to an Excel file
def save_to_excel(data, file_path):
    try:
        df = pd.json_normalize(data)
        df.to_excel(file_path, index=False)
        logger.info("Findings saved to Excel successfully")
    except Exception as e:
        logger.error("Failed to save findings to Excel: %s", e)

# Defining a method to upload the previously generated Excel file of findings to the S3 bucket.  
def upload_to_s3(file_path, bucket_name, object_name):
    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        logger.info("File uploaded to S3 successfully")
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to upload file to S3: %s", error)
        raise ValueError('An error occurred: {}'.format(error))


# Generating a presigned URL for the uploaded report file
def generate_presigned_url(bucket_name, object_name):
    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_name},
            ExpiresIn=86400)  # URL expira en 1 día
        logger.info("Presigned URL generated successfully")
        return presigned_url
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to generate pre-signed URL: %s", error)
        return None
        

# Publishing the message and URL to the SNS topic
def publish_to_sns(url, topic_arn):
    
    message = f"Hola, el reporte de hallazgos de ECR ya se encuentra listo. Puedes acceder a él mediante esta URL: {url}"
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject='ECR Findings Report'
        )
        logger.info("Message published to SNS successfully")
        return response
    except botocore.exceptions.ClientError as error:
        logger.error("Failed to publish message to SNS: %s", error)
        return None

# Lambda handler function
def lambda_handler(event, context):
    # Lambda function main execution starts here
    registry_id = get_registry_id()
    if not registry_id:
        return {
            'statusCode': 500,
            'body': 'Failed to get registry ID'
        }

    image_ids = get_list_images(registry_id, repository_name)
    if not image_ids:
        return {
            'statusCode': 404,
            'body': 'No images found'
        }

    all_findings = []
    for image in image_ids:
        image_findings = get_image_scan_findings(registry_id, repository_name, image)
        all_findings.extend(process_findings(image_findings))

    if not all_findings:
        logger.info("No findings found.")
        return {
            'statusCode': 404,
            'body': 'No findings found'
        }

    file_path = '/tmp/ecr_findings_report.xlsx'
    # Adding a timestamp for the generated report every time it is uploaded.
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    object_name = f'ecr_findings_report_{timestamp}.xlsx'
    save_to_excel(all_findings, file_path)

    # Check if bucket exists and create it if it does not
    try:
        list_buckets = s3_client.list_buckets().get('Buckets', [])
        if bucket_name not in [bucket['Name'] for bucket in list_buckets]:
            s3_client.create_bucket(
                ACL='private',
                Bucket=bucket_name
            )
       
        upload_to_s3(file_path, bucket_name, object_name)
        
        # Generating a presigned URL
        url = generate_presigned_url(bucket_name, object_name)
        if url:
            publish_to_sns(url, topic_arn)
    except botocore.exceptions.ClientError as error:
        logger.error("An error occurred: %s", error)
        return {
            'statusCode': 500,
            'body': f'Error creating bucket or uploading file: {error}'
        }

    return {
        'statusCode': 200,
        'body': 'Findings processed and uploaded successfully'
    }

