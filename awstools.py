#!/usr/bin/python3

from configparser import ConfigParser
from botocore.client import Config

import subprocess
import base64
import boto3
import click
import json
import sys
import re
import os

set_debug = False
set_profile = 'default'
set_region = None
ip_to_use = 'PrivateIpAddress'

def load_defaults(config_file):
    global set_debug, set_profile, set_region, ip_to_use

    try:
        config = ConfigParser()
        config.read(config_file)

        try:
            set_debug = config.getboolean('awstools', 'debug')
        except:
            set_debug = False

        try:
            set_profile = config.get('aws', 'profile').strip('"').strip("'").strip()
        except:
            set_profile = 'default'

        try:
            set_region = config.get('aws', 'region').strip('"').strip("'").strip()
        except:
            set_region = None

        try:
            ip_to_use = config.get('aws', 'useIP').strip('"').strip("'").strip()
        except:
            ip_to_use = 'PrivateIpAddress'

    except:
        pass

@click.group()
@click.option('--profile', default=None, help='AWS profile', type=str)
@click.option('--region', default=None, help='AWS region', type=str)
@click.option('--debug', is_flag=True, default=False, help='set debug mode')
def awstools(profile, region, debug):
    global set_debug, set_profile, set_region

    if profile:
        os.environ["AWS_PROFILE"] = profile
    else:
        os.environ["AWS_PROFILE"] = set_profile
    
    set_profile = profile
    set_region = region
    set_debug = debug

#
# EC2
#

ec2_client = None

def init_ec2_client():
    global ec2_client

    try:
        if set_region:
            ec2_client = boto3.client(service_name='ec2', region_name=set_region)
        else:
            ec2_client = boto3.client(service_name='ec2')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_search_ec2_instances_by_id(instance_id):
    global set_debug, set_profile, set_region

    try:
        if set_region:
            ec2 = boto3.client(service_name='ec2', region_name=set_region)
        else:
            ec2 = boto3.client(service_name='ec2')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

    response = ec2.describe_instances(InstanceIds=[ instance_id ])

    return response["Reservations"]

def aws_search_ec2_instances_by_name(name):
    global set_debug, set_profile, set_region

    try:
        if set_region:
            ec2 = boto3.client(service_name='ec2', region_name=set_region)
        else:
            ec2 = boto3.client(service_name='ec2')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

    if name:
        filter = {}
        filter['Name'] = 'tag:Name'
        filter['Values'] = [ name ]
        instance_filter = [ filter ]

        response = ec2.describe_instances(Filters=instance_filter)
    else:
        response = ec2.describe_instances()

    return response["Reservations"]

def aws_ec2_describe_ami(ami):

    ec2 = boto3.resource('ec2')
    image = ec2.Image(ami)

    return image

def print_instance(instance_name, instance_id, instance_ip, instance_state=None):
    if instance_state:
        print("{: <60} {: <20} {: <20} {}".format(instance_name, instance_ip, instance_id, instance_state))
    else:
        print("{: <60} {: <20} {}".format(instance_name, instance_ip, instance_id ))

@awstools.group()
def ec2():
    pass

@ec2.command()
@click.argument('name', default='')
@click.option('--running', is_flag=True, default=False, help='show only running instances')
@click.option('--connect', is_flag=True, default=False, help='connect to this instance')
@click.pass_context
def search(ctx, name, running, connect):
    """search EC2 instances that it's names contains a string"""
    global set_debug, ip_to_use

    if connect:
        ctx.invoke(ssh, host=name)
        return

    reservations = aws_search_ec2_instances_by_name(name=None)

    for reservation in reservations:
        for instance in reservation["Instances"]:
            try:
                name_found = False
                for tag in instance['Tags']:
                    if tag['Key']=='Name':
                        name_found = True
                        if name in tag['Value'] or not name:
                            if running and instance['State']['Name']=='running':
                                print_instance(tag['Value'], instance[ip_to_use], instance['InstanceId'])
                            else:
                                print_instance(tag['Value'], instance[ip_to_use], instance['InstanceId'], instance['State']['Name'])
                if not name and not name_found:
                            if running and instance['State']['Name']=='running':
                                print_instance('-', instance[ip_to_use], instance['InstanceId'])
                            else:
                                print_instance('-', instance[ip_to_use], instance['InstanceId'], instance['State']['Name'])
            except:
                pass
    
@ec2.command()
@click.argument('host')
@click.pass_context
def ssh(ctx, host):
    """ssh to a EC2 instance by name"""
    global set_debug, ip_to_use

    if host.startswith('i-'):
        reservations = aws_search_ec2_instances_by_id(host)
    else:
        reservations = aws_search_ec2_instances_by_name(host)

    if not reservations:
        reservations = aws_search_ec2_instances_by_name('*'+host+'*')

    candidates = []
    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance['State']['Name']=='running':
                candidates.append(instance[ip_to_use])

    if len(candidates) > 1:
        if set_debug:
            print(str(candidates))
        ctx.invoke(search, name=host, running=True)
        return

    try:
        subprocess.check_call(['ssh', candidates[0]])
        return
    except Exception as e:
        if set_debug:
            print(str(e))
        return
    sys.exit('Not found')

# @ec2.command()
# @click.argument('ami')
# def show_ami(ami):
#     image = aws_ec2_describe_ami(ami)

#     # TODO

@ec2.command()
@click.argument('ami')
def show_ami_launchpermissions(ami):
    global ec2_client

    if not ec2_client:
        init_ec2_client()

    response = ec2_client.describe_image_attribute(
                                                    Attribute='launchPermission',
                                                    ImageId=ami,
                                                    DryRun=False
                                                )
    # print(str(response['LaunchPermissions']))

    for launchpermission in response['LaunchPermissions']:
        if 'UserId' in launchpermission.keys():
            print("{: <15} {}".format('UserId', launchpermission['UserId']))
        if 'Group' in launchpermission.keys():
            print("{: <15} {}".format('Group', launchpermission['Group']))

@ec2.command()
@click.argument('ami')
@click.option('--account',  multiple=True, default=[], help='Add account to LaunchPermissions')
def add_ami_launchpermissions(ami, account):
    global ec2_client

    if not ec2_client:
        init_ec2_client()
    
    accounts = []
    for i in account:
        accounts.append(i)

    if accounts:
        response = ec2_client.modify_image_attribute(
                                                ImageId=ami, 
                                                OperationType='add', 
                                                Attribute='launchPermission', 
                                                UserIds=accounts
                                            )
        print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId'])

@ec2.command()
@click.argument('keypair')
@click.option('--pub-file',  help='public side to import', type=click.File('r'), default=sys.stdin)
def import_keypair(keypair, pub_file):
    global ec2_client

    if not ec2_client:
        init_ec2_client()
    
    pub_bytes = bytes(pub_file.read(), 'utf-8')

    response = ec2_client.import_key_pair(
                                            DryRun=False,
                                            KeyName=keypair,
                                            PublicKeyMaterial=pub_bytes,
                                        )
    print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId']+' KeyFingerprint: '+response['KeyFingerprint'])



#
# route53
#

route53_client = None

def init_route53_client():
    global route53_client

    try:
        if set_region:
            route53_client = boto3.client(service_name='route53', region_name=set_region)
        else:
            route53_client = boto3.client(service_name='route53')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_list_route53_zones(max_zones):
    global set_debug, set_profile, set_region, route53_client

    if not route53_client:
        init_route53_client()

    response = route53_client.list_hosted_zones(MaxItems=max_zones)

    return response['HostedZones']


@awstools.group()
def route53():
    pass

@route53.command()
@click.option('--max-zones', default='100', help='max number of zones', type=str)
@click.option('--public', is_flag=True, default=False, help='show only public zones')
@click.option('--private', is_flag=True, default=False, help='show only private zones')
def list(max_zones, public, private):
    """list route53 zones"""
    for zone in aws_list_route53_zones(max_zones):
        if (public and not zone['Config']['PrivateZone']) or (private and zone['Config']['PrivateZone']) or (not public and not private):
            print("{: <60} {: <20} {: <60} {}".format(zone['Name'], 'private' if zone['Config']['PrivateZone'] else 'public', zone['Id'], zone['ResourceRecordSetCount']))

def aws_route53_zone_exists(zone_id):
    global route53_client

    if not route53_client:
        init_route53_client()

    zone = route53_client.get_hosted_zone(Id=zone_id)

    return zone['HostedZone']['Id'] == zone_id

def aws_route53_get_zone_name(zone_id):
    global route53_client

    if not route53_client:
        init_route53_client()

    zone = route53_client.get_hosted_zone(Id=zone_id)

    return zone['HostedZone']['Name']

def aws_route53_list_resource_record_sets(zone_id):
    global set_debug, set_profile, set_region, route53

    max_items = '200'

    if not route53_client:
        init_route53_client()

    if aws_route53_zone_exists(zone_id):
        batch = route53_client.list_resource_record_sets(
                                            HostedZoneId=zone_id,
                                            MaxItems=max_items
                                        )
        records = batch['ResourceRecordSets']
        while batch['IsTruncated']:
            batch = route53_client.list_resource_record_sets(
                                                HostedZoneId=zone_id,
                                                StartRecordName=batch['NextRecordName'],
                                                StartRecordType=batch['NextRecordType'],
                                                MaxItems=max_items
                                            )
            records += batch['ResourceRecordSets']
        return records
    else:
        sys.exit('zone '+zone_id+' not found')

@route53.command()
@click.argument('zone-id')
@click.option('--include-not-importable', is_flag=True, default=False, help='include NS and SOA records')
@click.option('--exclude-domain-aws-validation', is_flag=True, default=False, help='exclude .acm-validations.aws. records')
@click.option('--domain-aws-validation', is_flag=True, default=False, help='only include .acm-validations.aws. records')
def export_records(zone_id, include_not_importable, exclude_domain_aws_validation, domain_aws_validation):
    """export zone records to JSON"""
    records = aws_route53_list_resource_record_sets(zone_id)
    
    zone_name = aws_route53_get_zone_name(zone_id)

    if not include_not_importable:
        records_to_remove = []
        for record in records:
            if (record['Name']==zone_name and record['Type']=='NS') or (record['Name']==zone_name and record['Type']=='SOA'):
                records_to_remove.append(record)
        for record in records_to_remove:
            records.remove(record)

    if exclude_domain_aws_validation or domain_aws_validation:
        aws_validation_records = []
        for record in records:
            try:
                if record['Name'][0]=='_' and record['Type']=='CNAME':
                    for resourcerecord in record['ResourceRecords']:
                        try:
                            if resourcerecord['Value'].endswith('.acm-validations.aws.'):
                                aws_validation_records.append(record)
                                continue
                        except:
                            pass  
            except:
                pass
        if exclude_domain_aws_validation:
            for record in aws_validation_records:
                records.remove(record)
        elif domain_aws_validation:
            print(json.dumps(aws_validation_records))
            return

    print(json.dumps(records))

@route53.command()
@click.argument('zone-id')
@click.option('--import-file',  help='file to read json data from', type=click.File('r'), default=sys.stdin)
@click.option('--tr', default='', help='original zone name', type=str)
@click.option('--tr-hz', default='', help='original hosted zone id', type=str)
def import_records(zone_id, import_file, tr, tr_hz):
    """import zone records from file or stdin in JSON format"""
    global set_debug, route53_client

    if tr:
        if tr[-1]!='.':
            tr+='.'

    if tr_hz:
        if '/hostedzone/' in tr_hz:
            tr_hz = tr_hz.lstrip('/hostedzone/')

    if not aws_route53_zone_exists(zone_id):
        sys.exit('zone not found')

    try:
        records = json.load(import_file)
    except Exception as e:
        sys.exit('ERROR reading input data: '+str(e))

    zone_name = aws_route53_get_zone_name(zone_id)

    changes = []
    for record in records:
        if tr:
            record['Name']=re.sub(tr+'$', zone_name, record['Name'])
        if tr_hz:
            try:
                if record['AliasTarget']['HostedZoneId']==tr_hz:
                    record['AliasTarget']['HostedZoneId']=zone_id.lstrip('/hostedzone/')
            except:
                pass
        change = {}
        change['Action']='UPSERT'
        change['ResourceRecordSet']=record
        changes.append(change)

    changebatch = {}
    changebatch['Changes']=changes

    if not route53_client:
        init_route53_client()

    if set_debug:
        print(json.dumps(changebatch))

    response = route53_client.change_resource_record_sets(ChangeBatch=changebatch, HostedZoneId=zone_id.lstrip('/hostedzone/'))

    print("{: <60} {}".format(response['ChangeInfo']['Id'], response['ChangeInfo']['Status']))

#
# eks
#

eks_client = None

def init_eks_client():
    global eks_client

    try:
        if set_region:
            eks_client = boto3.client(service_name='eks', region_name=set_region)
        else:
            eks_client = boto3.client(service_name='eks')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_list_eks_clusters():
    global set_debug, eks_client

    if not eks_client:
        init_eks_client()

    response = eks_client.list_clusters()

    return response['clusters']

def aws_eks_describe_cluster(name):
    global set_debug, eks_client

    if not eks_client:
        init_eks_client()

    response = eks_client.describe_cluster(name=name)

    if set_debug:
        print(str(response))

    return response['cluster']

@awstools.group()
def eks():
    pass

@eks.command()
@click.argument('cluster')
@click.option('--kubeconfig', default='', help='kubeconfig file', type=str)
def set_context(cluster, kubeconfig):
    """import EKS cluster context to kubectl"""
    global set_debug, set_profile, set_region, ip_to_use
    if cluster in aws_list_eks_clusters():
        try:
            # aws eks --profile profile update-kubeconfig --name clustername
            aws_eks_command = ['aws', 'eks', '--profile', set_profile]
            if set_region:
                aws_eks_command.append('--region')
                aws_eks_command.append(set_region)
            aws_eks_command.append('update-kubeconfig')
            aws_eks_command.append('--name')
            aws_eks_command.append(cluster)
            if kubeconfig:
                aws_eks_command.append('--kubeconfig')
                aws_eks_command.append(kubeconfig)
            if set_debug:
                print(' '.join(aws_eks_command))
            subprocess.check_call(aws_eks_command)
            return
        except Exception as e:
            if set_debug:
                print(str(e))
            return   

@eks.command()
def list():
    """list EKS clusters"""

    for cluster in aws_list_eks_clusters():
        cluster_info = aws_eks_describe_cluster(cluster)
        print("{: <60} {}".format(cluster, cluster_info['arn']))

#
# S3
#

s3_client = None
set_endpoint = None
set_access_key = None
set_secret = None

def init_s3_client():
    global s3_client, set_endpoint, set_access_key, set_secret

    try:
        if set_region:
            s3_client = boto3.client(service_name='s3', region_name=set_region)
        else:
            if set_endpoint:
                s3_client = boto3.client(
                                            service_name='s3',
                                            endpoint_url=set_endpoint,
                                            aws_access_key_id=set_access_key,
                                            aws_secret_access_key=set_secret,
                                            config=Config(signature_version='s3v4'),
                                        )
            else:
                s3_client = boto3.client(service_name='s3')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

@awstools.group()
@click.option('--endpoint', default=None, help='URL S3 endpoint', type=str)
@click.option('--access-key', default=None, help='S3 access key', type=str)
@click.option('--secret', default=None, help='S3 secret for the access key', type=str)
def s3(endpoint, access_key, secret):
    global set_endpoint, set_access_key, set_secret
    
    set_endpoint = endpoint
    set_access_key = access_key
    set_secret = secret

@s3.command()
@click.option('--region', default=None, help='region', type=str)
@click.argument('bucket')
def create_bucket(bucket, region):
    """ create new bucket"""
    global s3_client

    if not s3_client:
        init_s3_client()

    if region:
        location = {'LocationConstraint': region}
        response = s3_client.create_bucket(Bucket=bucket, CreateBucketConfiguration=location)
    else:
        response = s3_client.create_bucket(Bucket=bucket)
    
    print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId'])

@s3.command()
def list():
    """list S3 buckets"""
    global s3_client

    if not s3_client:
        init_s3_client()

    response = s3_client.list_buckets()

    for bucket in response['Buckets']:
        print("{: <60} {}".format(bucket['Name'], str(bucket['CreationDate'])))

# @s3.command()
# @click.argument('bucket')
# @click.argument('file')
# @click.option('--public', is_flag=True, default=False, help='public ACL')
# @click.option('--import-file',  help='file to read json data from', type=click.File('r'), default=sys.stdin)
# def put(bucket):
#     """put file"""
#     global s3_client

#     if not s3_client:
#         init_s3_client()
    
#     if public:
#         acl = 'public'
#     else:
#         acl = 'private'


@s3.command()
@click.argument('bucket')
@click.option('--path', default='/', help='path', type=str)
def ls(bucket, path):
    """list bucket contents"""
    global s3_client

    if not s3_client:
        init_s3_client()

    if path=='/':
        try:
            for bucket_object in s3_client.list_objects(Bucket=bucket)['Contents']:
                print("{: <60} {}".format(bucket_object['Key'], str(bucket_object['LastModified'])))
        except:
            pass
    else:
        for bucket_object in s3.list_objects_v2(Bucket=bucket, Prefix = path, MaxKeys=100 )['Contents']:
            print("{: <60} {}".format(bucket_object['Key'], str(bucket_object['LastModified'])))

#
# SM SecretManager
#

sm_client = None

def init_sm_client():
    global sm_client

    try:
        if set_region:
            sm_client = boto3.client(service_name='secretsmanager', region_name=set_region)
        else:
            sm_client = boto3.client(service_name='secretsmanager')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_secretsmanager_list():
    global sm_client

    max_items = 100

    if not sm_client:
        init_sm_client()

    batch = sm_client.list_secrets(MaxResults=max_items)
    #print(str(batch))
    records = batch['SecretList']
    while 'NextToken' in batch.keys():
        batch = sm_client.list_secrets(
                                        MaxResults=max_items,
                                        NextToken=batch['NextToken']
                                        )

        records += batch['SecretList']
    return records

@awstools.group()
def sm():
    pass

@sm.command()
def list():
    """list secrets"""

    secrets = aws_secretsmanager_list()

    for secret in secrets:
        print(str(secret))

#
# SSM
#

ssm_client = None

def init_ssm_client():
    global ssm_client

    try:
        if set_region:
            ssm_client = boto3.client(service_name='ssm', region_name=set_region)
        else:
            ssm_client = boto3.client(service_name='ssm')
    except Exception as e:
        sys.exit('ERROR: '+str(e))


def aws_ssm_list_parameters():
    global ssm_client

    max_items = 50

    if not ssm_client:
        init_ssm_client()

    batch = ssm_client.describe_parameters(MaxResults=max_items)
    #print(str(batch))
    records = batch['Parameters']
    while 'NextToken' in batch.keys():
        batch = ssm_client.describe_parameters(
                                                MaxResults=max_items,
                                                NextToken=batch['NextToken']
                                            )

        records += batch['Parameters']
    return records

@awstools.group()
def ssm():
    pass

@ssm.command()
def list():
    """list parameters"""

    for parameter in aws_ssm_list_parameters():
        #print(str(parameter))
        if 'Description' in parameter.keys():
            print("{: <60} {: <15} {: <80} {}".format(parameter['Name'], parameter['Type'], parameter['Description'], str(parameter['LastModifiedDate'])))
        else:
            print("{: <60} {: <15} {: <80} {}".format(parameter['Name'], parameter['Type'], '', str(parameter['LastModifiedDate'])))

@ssm.command()
@click.argument('parameter')
@click.option('--output-json', is_flag=True, default=False, help='output as JSON')
def get(parameter, output_json):
    """get parameter"""
    global ssm_client

    if not ssm_client:
        init_ssm_client()

    try:
        parameter = ssm_client.get_parameter(Name=parameter, WithDecryption=True)['Parameter']

        parameter_json = {}

        for key in [ 'Name', 'Value', 'Type', 'ARN', 'Description']:
            if key in parameter.keys():
                parameter_json[key] = parameter[key]
            else:
                parameter_json[key] = ''

        if output_json:
            print(json.dumps(parameter_json))
        else:
            print("{: <50} {: <30} {: <15} {}".format(parameter_json['Name'], parameter_json['Value'], parameter_json['Type'], parameter_json['ARN']))
    except Exception as e:
        sys.exit('Parameter not found: '+str(e))

@ssm.command()
@click.option('--import-file',  help='file to read json data from', type=click.File('r'), default=sys.stdin)
@click.option('--rename',  default=None, help='Rename parameter to')
@click.option('--overwrite', is_flag=True, default=False, help='overwrite parameter')
def put(import_file, rename, overwrite):
    """import parameter from JSON"""
    parameter_json = json.load(import_file)

    if not ssm_client:
        init_ssm_client()

    if rename:
        parameter_name = rename
    else:
        parameter_name = parameter_json['Name']

    response = ssm_client.put_parameter(
                                Name=parameter_name,
                                Value=parameter_json['Value'],
                                Description=parameter_json['Description'],
                                Type=parameter_json['Type'],
                                Overwrite=overwrite,
                            )
    
    print(str(response['ResponseMetadata']['RequestId']))

@ssm.command()
@click.argument('parameter')
@click.argument('value')
@click.option('--description', default='', help='parameter description', type=str)
@click.option('--overwrite', is_flag=True, default=False, help='overwrite parameter')
def set(parameter, value, description, overwrite):
    """set SecureString parameter"""
    if not ssm_client:
        init_ssm_client()

    response = ssm_client.put_parameter(
                                Name=parameter,
                                Value=value,
                                Description=description,
                                Type='SecureString',
                                Overwrite=overwrite,
                            )
    
    print(str(response['ResponseMetadata']['RequestId']))

@ssm.command()
@click.argument('parameter')
def delete(parameter):
    """delete parameter"""
    global ssm_client

    if not ssm_client:
        init_ssm_client()

    try:
        response = ssm_client.delete_parameter(Name=parameter)

        print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId'])
    except Exception as e:
        sys.exit('Parameter not found: '+str(e))

#
# KMS
#

kms_client = None

def init_kms_client():
    global kms_client

    try:
        if set_region:
            kms_client = boto3.client(service_name='kms', region_name=set_region)
        else:
            kms_client = boto3.client(service_name='kms')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_kms_list():
    global kms_client

    max_items = 1000

    if not kms_client:
        init_kms_client()

    batch = kms_client.list_keys(Limit=max_items)
    #print(str(batch))
    key_ids = batch['Keys']
    while 'NextMarker' in batch.keys():
        batch = kms_client.list_keys(
                                        Limit=max_items,
                                        Marker=batch['NextMarker']
                                    )

        key_ids += batch['Keys']
    records = []

    for key in key_ids:
        response = kms_client.describe_key(KeyId=key['KeyId'])
        records.append(response['KeyMetadata'])
    return records

def aws_kms_get_key_policies(key):
    global kms_client

    max_items = 1000

    if not kms_client:
        init_kms_client()

    batch = kms_client.list_key_policies(KeyId=key, Limit=max_items)
    #print(str(batch))
    records = batch['PolicyNames']
    while 'NextMarker' in batch.keys():
        batch = kms_client.list_keys(
                                        Limit=max_items,
                                        Marker=batch['NextMarker']
                                    )

        records += batch['PolicyNames']

    return records

@awstools.group()
def kms():
    pass

@kms.command()
def list():
    """list keys"""
    for key in aws_kms_list():
        #print(str(key))
        print("{: <50} {}".format(key['KeyId'], key['Description']))

@kms.command()
@click.argument('key')
def get_key_policies(key):
    """get key policies"""

    policies = aws_kms_get_key_policies(key)

    for policy in policies:
        print(str(policy))

@kms.command()
@click.argument('key')
@click.argument('policy')
def get_key_policy(key, policy):
    """get key policy"""
    global kms_client

    if not kms_client:
        init_kms_client()

    response = kms_client.get_key_policy(KeyId=key, PolicyName=policy)

    print(response['Policy'])

@kms.command()
@click.argument('key')
@click.argument('policy')
@click.option('--policy-file',  help='file to read json data from', type=click.File('r'), default=sys.stdin)
def set_key_policy(key, policy, policy_file):
    """set key policy"""
    global kms_client

    if not kms_client:
        init_kms_client()

    response = kms_client.put_key_policy(
                                            KeyId=key,
                                            PolicyName=policy,
                                            Policy=policy_file.read()
                                        )

    print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId'])

#
# ACM
#

acm_client = None

def init_acm_client():
    global acm_client

    try:
        if set_region:
            acm_client = boto3.client(service_name='acm', region_name=set_region)
        else:
            acm_client = boto3.client(service_name='acm')
    except Exception as e:
        sys.exit('ERROR: '+str(e))

def aws_acm_list():
    global acm_client

    max_items = 1000

    if not acm_client:
        init_acm_client()

    batch = acm_client.list_certificates(MaxItems=max_items)
    #print(str(batch))
    records = batch['CertificateSummaryList']
    while 'NextToken' in batch.keys():
        batch = acm_client.list_certificates(
                                        MaxItems=max_items,
                                        NextToken=batch['NextToken']
                                    )

        records += batch['CertificateSummaryList']
    
    return records

@awstools.group()
def acm():
    pass

@acm.command()
def list():
    """list certificates"""

    certs = aws_acm_list()

    for cert in certs:
        print("{: <50} {}".format(cert['CertificateArn'], cert['DomainName']))

#
# RDS
#

rds_client = None

def init_rds_client():
    global rds_client

    try:
        if set_region:
            rds_client = boto3.client(service_name='rds', region_name=set_region)
        else:
            rds_client = boto3.client(service_name='rds')
    except Exception as e:
        sys.exit('ERROR: '+str(e))


def aws_acm_list_db_instances():
    global rds_client

    max_items = 100

    if not rds_client:
        init_rds_client()

    batch = rds_client.describe_db_instances(MaxRecords=max_items)
    #print(str(batch))
    records = batch['DBInstances']
    while 'Marker' in batch.keys():
        batch = rds_client.describe_db_instances(
                                        MaxRecords=max_items,
                                        Marker=batch['Marker']
                                    )

        records += batch['DBInstances']
    
    return records

@awstools.group()
def rds():
    pass

@rds.command()
def list():
    """list dbs instances"""

    dbinstances = aws_acm_list_db_instances()

    for dbinstance in dbinstances:
        print("{: <50} {: <20} {}".format(dbinstance['DBInstanceIdentifier'], dbinstance['Engine'], str(dbinstance['DBParameterGroups'])))

if __name__ == '__main__':
    load_defaults(os.path.join(os.getenv("HOME"), '.awstools/config'))
    awstools()
