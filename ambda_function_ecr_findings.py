#!/bin/python3.10
#####################################################################
# Script developed by Sheyla Leacock
#####################################################################

#Importing the necessary libraries 
import boto3
import json
import pandas as pd
from datetime import datetime
import botocore.exceptions
#defining boto3 clients for the connection to the AWS services
ecr_client = boto3.client('ecr')
s3_client = boto3.client('s3')
#defining the bucket name variable to store the findings
bucket_name = 's3-ecr-findings'
repository_name = 'ecr_test'
def lambda_handler(event, context):
    try:
        #defining the method to obtain the ECR registry information and getting the registryId that will be needed as a parameter for the next method.
        get_registry = ecr_client.describe_registry()
        get_registry_id =  get_registry.get("registryId")
        #defining the method to obtain the information of the repositories, by sending the registryId parameter that was previously obtained
        get_repositories = ecr_client.describe_repositories(
            registryId=get_registry_id
            )
        
        #defining the method to list all the ECR images by sending the registryId and repositoryName parameters.        
        list_images = ecr_client.list_images(
            registryId=get_registry_id,
            repositoryName = repository_name
            )
    
        #defining a list to store findings information
        all_findings = []
        k=0
        #defining a loop cycle to iterate through the list of images obtained previously
        for j in list_images:
            #while iterating, i obtain the tags and digests of the images and save them on variables
            while k < len(list_images['imageIds']):
                image_digest = list_images['imageIds'][k]['imageDigest']
                image_tag = list_images['imageIds'][k]['imageTag']
                k+=1
       
        #defining the method to describe the findings of an image scan by sending the previously obtained values of the registryId, repositoryName and image details as a parameters.        
        get_findings = ecr_client.describe_image_scan_findings(
            registryId=get_registry_id,
            repositoryName = repository_name,
            imageId={
                'imageDigest': image_digest,
                'imageTag': image_tag
            },
            #setting the maximum number of results to get in one call
            maxResults=1000
            )
        #adding the obtained results at the end of the list of findings
        all_findings.extend(get_findings['imageScanFindings']['findings'])
        #defining a loop to iterate on get_findings if nextToken is present in the response. This means, that they are still findings to get, so another call is necessary.
        while 'nextToken' in get_findings:
            #assigning the nextToken in the response to the variable token to use it in the next condition.
            token = get_findings['nextToken']
            #another call to the same method only while the condition of nextToken is present
            get_findings = ecr_client.describe_image_scan_findings(
            registryId=get_registry_id,
            repositoryName = repository_name,
            imageId={
                'imageDigest': image_digest,
                'imageTag': image_tag
            },
            #assigning the nextToken parameter with the value of the token, obtained previously from the first call
            nextToken = token,
            maxResults=1000
            )
        #adding the obtained results at the end of the list of findings
        all_findings.extend(get_findings['imageScanFindings']['findings'])
    #managing any exceptions that can occur.       
    except botocore.exceptions.ClientError as error:
        raise ValueError('An error ocurred: {}'.format(error))
      
            
    try:
        #using pandas library method json_normalize to normalize the Json list of findings into a table
        findings_data = pd.json_normalize(all_findings)
        #converting the normalized data to a excel file
        findings_data.to_excel('/tmp/ecr_findings_report.xlsx', index = False)
    #managing any exceptions that can occur. 
    except Exception as e:
        raise Exception('An error ocurred: {}'.format(e))
    
    try:
        #defining the method to list all the buckets
        list_buckets = s3_client.list_buckets()
        #a condition to validate if the bucket name is not present in the buckets list. if true, then attempt to create the new bucket with a private ACL.
        if bucket_name not in list_buckets:
            create_bucket = s3_client.create_bucket(
                ACL = 'private',
                Bucket = bucket_name
                )
        #defining a method to upload the previously generated excel file of findings to the s3 bucket , adding it a timestamp everytime it is uploaded.   
        upload_report = s3_client.upload_file('/tmp/ecr_findings_report.xlsx', bucket_name,'ecr_findings_report_'+ str(datetime.now()) +'.xlsx')
    #managing any exceptions that can occur. 
    except botocore.exceptions.ClientError as error:
        raise ValueError('An error ocurred: {}'.format(error))
        
    return {
        'statusCode': 200,
        'body': json.dumps('Lambda executed')
        
    }