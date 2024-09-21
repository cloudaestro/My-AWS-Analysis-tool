import boto3
import json
from datetime import datetime, timedelta

class EnterpriseAWSManager:
    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.s3 = boto3.client('s3')
        self.cloudwatch = boto3.client('cloudwatch')
        self.iam = boto3.client('iam')
        self.cost_explorer = boto3.client('ce')

    def get_running_instances(self):
        instances = self.ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        return [instance for reservation in instances['Reservations'] for instance in reservation['Instances']]

    def analyze_s3_buckets(self):
        buckets = self.s3.list_buckets()['Buckets']
        bucket_analysis = []
        for bucket in buckets:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket['Name'])
            versioning = self.s3.get_bucket_versioning(Bucket=bucket['Name'])
            bucket_analysis.append({
                'Name': bucket['Name'],
                'CreationDate': bucket['CreationDate'].isoformat(),
                'Encryption': encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', []),
                'Versioning': versioning.get('Status', 'Not enabled')
            })
        return bucket_analysis

    def get_cloudwatch_metrics(self, instance_id):
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        metrics = self.cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'cpu',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': 'CPUUtilization',
                            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                        },
                        'Period': 3600,
                        'Stat': 'Average'
                    },
                    'ReturnData': True
                },
                {
                    'Id': 'network',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': 'NetworkIn',
                            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                        },
                        'Period': 3600,
                        'Stat': 'Sum'
                    },
                    'ReturnData': True
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        return metrics['MetricDataResults']

    def analyze_iam_policies(self):
        policies = self.iam.list_policies(Scope='Local')['Policies']
        policy_analysis = []
        for policy in policies[:5]:  # Analyze the first 5 policies for brevity
            policy_version = self.iam.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )['PolicyVersion']
            policy_analysis.append({
                'PolicyName': policy['PolicyName'],
                'PolicyDocument': policy_version['Document']
            })
        return policy_analysis

    def get_cost_and_usage(self):
        end_date = datetime.utcnow().date()
        start_date = end_date - timedelta(days=30)
        response = self.cost_explorer.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.isoformat(),
                'End': end_date.isoformat()
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost']
        )
        return response['ResultsByTime']

    def generate_report(self):
        instances = self.get_running_instances()
        report = {
            'RunningInstances': len(instances),
            'InstanceDetails': instances[:2],  # Include details of first 2 instances
            'S3Analysis': self.analyze_s3_buckets(),
            'CloudWatchMetrics': self.get_cloudwatch_metrics(instances[0]['InstanceId']) if instances else [],
            'IAMPolicyAnalysis': self.analyze_iam_policies(),
            'CostAnalysis': self.get_cost_and_usage()
        }
        return report

def lambda_handler(event, context):
    manager = EnterpriseAWSManager()
    report = manager.generate_report()
    return {
        'statusCode': 200,
        'body': json.dumps(report, default=str)
    }.replit