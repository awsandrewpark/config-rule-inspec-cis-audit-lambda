import boto3
import botocore
import json
import logging
import time
import re
from botocore.exceptions import ClientError

def evaluate_compliance(configuration_item):
    region       = configuration_item['awsRegion']
    ssm_client   = boto3.client('ssm', region_name=region)
    myInstanceId = configuration_item['configuration']['instanceId']

    ssmresponse = ssm_client.send_command(
             InstanceIds=[ myInstanceId ],
             DocumentName="AWS-RunInspecChecks",
             Parameters={
                'sourceInfo':[ '{ "owner":"dev-sec", "repository":"cis-dil-benchmark", "path": "", "getOptions" : "branch:master", "tokenInfo":"{{ssm-secure:github-personal-token-InSpec}}" }' ],
                'sourceType': [ 'GitHub' ]
             })
    command_id = ssmresponse['Command']['CommandId']

    counter=0
    while True:
        try:
            output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=myInstanceId,
                PluginName='runInSpecLinux'
                )
            myStatus = output['Status']
            if myStatus == 'Success':
                print ("The execution of cis-dil-benchmark scanning completed successfully.  I will now check whether there are NON_COMPLIANT items.")
                message = output['StandardOutputContent']
                x = re.search("and 0 non-compliant",message)
                if not x:
                    annotation = "The ec2 instance " + myInstanceId +" is NOT compliant to the cis-dil-benchmark standard"
                    compliance_type = 'NON_COMPLIANT'
                else:
                    annotation = "The ec2 instance " + myInstanceId +" is compliant to the cis-dil-benchmark standard"
                    compliance_type = 'COMPLIANT'
                print (annotation)
            elif myStatus == 'Delivery Timed Out' or myStatus == 'Execution Timed Out' or myStatus == 'Failed' or myStatus == 'Canceled' or myStatus == 'Undeliverable' or myStatus == 'Terminated':
                annotation = "The execution of cis-dil-benchmark scanning was not successful.  I was not able to determine the state of the " + myInstanceId + " ec2 instance.  I will mark the instancer NON_COMPLIANT for now."
                compliance_type = 'NON_COMPLIANT'
            break
        except ClientError as e:
            counter += 1
            print('waiting for the scan result... %d'%counter)
            time.sleep(1)
    return {
        "compliance_type": compliance_type,
        "annotation": annotation
    }

def lambda_handler(event, context):
    print ("event: ",event)
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client('config')

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType':    invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':      invoking_event['configurationItem']['resourceId'],
               'ComplianceType':            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               'OrderingTimestamp':         invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
