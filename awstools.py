#!/usr/bin/python3

from configparser import ConfigParser

import subprocess
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

#
# EC2
#

def aws_search_ec2_instances(name):
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

def print_instance(instance_name, instance_id, instance_ip, instance_state=None):
    if instance_state:
        print("{: <60} {: <20} {: <20} {: <20}".format(instance_name, instance_ip, instance_id, instance_state))
    else:
        print("{: <60} {: <20} {: <20}".format(instance_name, instance_ip, instance_id ))

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
    
    set_region = region

    set_debug = debug

@awstools.group()
def ec2():
    pass

@ec2.command()
@click.argument('name', default='')
@click.option('--running', is_flag=True, default=False, help='show only running instances')
def search(name, running):
    """search EC2 instances that it's names contains a string"""
    global set_debug, ip_to_use

    reservations = aws_search_ec2_instances(name=None)

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

    reservations = aws_search_ec2_instances(host)

    if not reservations:
        reservations = aws_search_ec2_instances('*'+host+'*')

    if len(reservations) > 1:
        ctx.invoke(search, name=host, running=True)
        return

    for reservation in reservations:
        for instance in reservation["Instances"]:
            if instance['State']['Name']=='running':
                try:
                    subprocess.check_call(['ssh', instance[ip_to_use]])
                    return
                except Exception as e:
                    if set_debug:
                        print(str(e))
                    return
    sys.exit('Not found')

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
            print("{: <60} {: <20} {: <60} {: <20}".format(zone['Name'], 'private' if zone['Config']['PrivateZone'] else 'public', zone['Id'], zone['ResourceRecordSetCount']))

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
def export_records(zone_id, include_not_importable):
    """export zone records to JSON"""
    records = aws_route53_list_resource_record_sets(zone_id)
    
    zone_name = aws_route53_get_zone_name(zone_id)

    if not include_not_importable:
        for record in records:
            if (record['Name']==zone_name and record['Type']=='NS') or (record['Name']==zone_name and record['Type']=='SOA'):
                records.remove(record)
                
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

    print("{: <60} {: <20} ".format(response['ChangeInfo']['Id'], response['ChangeInfo']['Status']))

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
def set_context(cluster):
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
        print("{: <60} {: <20} ".format(cluster, cluster_info['arn']))

if __name__ == '__main__':
    load_defaults(os.path.join(os.getenv("HOME"), '.awstools/config'))
    awstools()
