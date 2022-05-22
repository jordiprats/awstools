#!/usr/bin/python3

from configparser import ConfigParser
from urllib import response
from botocore.client import Config

import subprocess
import base64
import random
import boto3
import click
import json
import sys
import re
import os

HOSTED_ZONE_PREFIX = '/hostedzone/'

set_debug = False
set_profile = 'default'
set_region = None
ip_to_use = 'PrivateIpAddress'
user_to_ssh = 'ec2-user'

def load_defaults(config_file):
  global set_debug, set_profile, set_region, ip_to_use, user_to_ssh

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

    try:
      user_to_ssh = config.get('aws', 'sshUser').strip('"').strip("'").strip()
    except:
      user_to_ssh = 'ec2-user'

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
# IAM
#

iam_client = None

def init_iam_client():
  global iam_client

  try:
    if set_region:
      iam_client = boto3.client(service_name='iam', region_name=set_region)
    else:
      iam_client = boto3.client(service_name='iam')
  except Exception as e:
    sys.exit('ERROR: '+str(e))

def iam_list_roles(name=None, prefix='/'):
  global iam_client

  if not iam_client:
    init_iam_client()

  batch = iam_client.list_roles(PathPrefix=prefix, MaxItems=100)

  if not name:
    list_roles = batch['Roles']
  else:
    list_roles = []
    for role in batch['Roles']:
      if name in role['RoleName']:
        list_roles.append(role)

  while batch['IsTruncated']:
    batch = iam_client.list_roles(PathPrefix=prefix, MaxItems=100, Marker=batch['Marker'])
    if not name:
      list_roles += batch['Roles']
    else:
      for role in batch['Roles']:
        if name in role['RoleName']:
          list_roles.append(role)
          break

  return list_roles

@awstools.group()
def iam():
  """ IAM related commands """
  pass

@iam.command()
@click.argument('name', default='')
@click.option('--prefix', default='/', help='use prefix', type=str)
def role(name, prefix):
  """list IAM roles"""
  global set_debug

  roles = iam_list_roles(name, prefix)
  # print(str(roles))

  for role in roles:
    print("{: <70} {: <25} {}".format(
                  role['Path']+role['RoleName'],
                  role['RoleId'],
                  role['Arn']))

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

def aws_ec2_terminate_instances_by_id(instance_ids=[], dryrun=False):
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  return ec2_client.terminate_instances(
                      InstanceIds=instance_ids,
                      DryRun=dryrun,
                    )

def aws_ec2_cpucredits_by_id(instance_id):
  global ec2_client

  if not ec2_client:
    init_ec2_client()
  
  response = ec2_client.describe_instance_credit_specifications(InstanceIds=[instance_id])

  return response

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

def print_instance(instance_name, instance_id, instance_ip, instance_launchtime, instance_keyname, instance_state=None):
  if instance_state:
    print("{: <60} {: <20} {: <20} {: <20} {}    {}".format(instance_name, instance_ip, instance_id, instance_state, instance_launchtime, instance_keyname))
  else:
    print("{: <60} {: <20} {: <20} {}    {}".format(instance_name, instance_ip, instance_id, instance_launchtime, instance_keyname ))

@awstools.group()
def ec2():
  """ EC2 related commands """
  pass

def ec2_get_instance_ip(instance):
  print(str(instance))
  return instance['InstanceId']

def ec2_get_instance_name(instance):
  try:   
    for tag in instance['Tags']:
      if tag['Key']=='Name':
        return tag['Value']
    return '-'
  except:
    return '-'            

def ec2_get_ip(instance, ip_type=None):
  global set_debug, ip_to_use
  try:
    if ip_type:
      if ip_type == 'public':
        ip_type_index = 'PublicIpAddress'
      elif ip_type == 'private':
        ip_type_index = 'PrivateIpAddress'
      else:
        ip_type_index = 'PublicIpAddress'
      return instance[ip_type_index]
    else:
      return instance[ip_to_use]
  except:
    return '-'

@ec2.command()
@click.argument('name', default='')
def cpucredits(name):
  """retrieve InstanceCreditSpecifications"""
  global set_debug

  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      cpucredits = aws_ec2_cpucredits_by_id(instance['InstanceId'])
      print("{: <60} {: <20} {: <20} {}".format(
                        ec2_get_instance_name(instance), 
                        instance['InstanceId'], 
                        instance['InstanceType'], 
                        cpucredits['InstanceCreditSpecifications'][0]['CpuCredits'])
                      )

@ec2.command()
@click.argument('name', default='')
@click.option('--no-title', is_flag=True, default=False, help='don\'t show column description')
def interfaces(name, no_title):
  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  base_format = "{: <30} {: <25} {: >20} {: >20}"

  if not no_title:
    print(base_format.format("InstanceName", "InstanceId", "NetworkInterfaces", "PrivateIpAddresses"))

  for reservation in reservations:
    for instance in reservation["Instances"]:
      count_eni = 0
      count_private_ips = 0
      # print(str(instance))

      # skip if instance is terminated
      if instance['State']['Name'] == 'terminated':
        continue

      for interface in instance['NetworkInterfaces']:
        count_eni += 1

        count_private_ips += len(interface['PrivateIpAddresses'])
        # print(str(interface))
      print(base_format.format(ec2_get_instance_name(instance), instance['InstanceId'], count_eni, count_private_ips))
  
def ec2_list_instances(ctx, name, all, connect, any, terminate, ip):
  """search EC2 running instances"""
  global set_debug

  if connect:
    ctx.invoke(ssh, host=name, any=any)
    return

  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  if terminate:
    for reservation in reservations:
      for instance in reservation["Instances"]:
        try:
          termination_response = aws_ec2_terminate_instances_by_id([instance['InstanceId']])
        except Exception as e:
          termination_response['ResponseMetadata']['RequestId'] = e
        print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance, ip), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "terminating: "+str(termination_response['ResponseMetadata']['RequestId']))
        
  else:
    for reservation in reservations:
      for instance in reservation["Instances"]:
        #print(str(instance))
        if all:
          print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance, ip), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], instance['State']['Name'])
        else:
          if instance['State']['Name']=='running':
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance, ip), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'])

@ec2.command()
@click.argument('name', default='')
@click.option('--all', is_flag=True, default=False, help='show all instances - default is to list just running instances')
@click.option('--connect', is_flag=True, default=False, help='connect to this instance')
@click.option('--any', is_flag=True, default=False, help='connect to any host that matches')
@click.option('--terminate', is_flag=True, default=False, help='terminate any instance that matches')
@click.option('--ip', default=None, help='IP to use for ssh')
@click.pass_context
def search(ctx, name, all, connect, any, terminate, ip):
  ec2_list_instances(ctx, name, all, connect, any, terminate, ip)

@ec2.command()
@click.argument('name', default='')
@click.option('--all', is_flag=True, default=False, help='show all instances - default is to list just running instances')
@click.option('--connect', is_flag=True, default=False, help='connect to this instance')
@click.option('--any', is_flag=True, default=False, help='connect to any host that matches')
@click.option('--terminate', is_flag=True, default=False, help='terminate any instance that matches')
@click.option('--ip', default=None, help='IP to use for ssh')
@click.pass_context
def list(ctx, name, all, connect, any, terminate, ip):
  ec2_list_instances(ctx, name, all, connect, any, terminate, ip)

@ec2.command()
@click.argument('host')
@click.argument('command', default='')
@click.option('--any', is_flag=True, default=False, help='connect to any host that matches')
@click.option('--ip', default=None, help='IP to use for ssh')
@click.pass_context
def ssh(ctx, host, command, any, ip):
  """ssh to a EC2 instance by name"""
  global set_debug

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
        candidates.append(ec2_get_ip(instance, ip))

  if len(candidates) > 1 and not any:
    if set_debug:
      print(str(candidates))
    ec2_list_instances(ctx=ctx, name=host, all=False, connect=False, any=False, terminate=False, ip=ip)
    return
  elif len(candidates) > 1 and any:
    random.shuffle(candidates)

  try:
    if command:
      call_command = ['ssh', user_to_ssh+'@'+candidates[0], command]
      if set_debug:
        print(str(call_command))
      ret = subprocess.check_call()
    else:
      call_command = ['ssh', user_to_ssh+'@'+candidates[0]]
      if set_debug:
        print(str(call_command))
      ret = subprocess.check_call(call_command)
    sys.exit(ret)
  except Exception as e:
    if set_debug:
      print(str(e))
    return

@ec2.command()
@click.argument('host')
@click.argument('command')
@click.option('--no-instance-id', is_flag=True, default=False, help='connect to any host that matches')
@click.option('--ip', default=None, help='IP to use for ssh')
def cssh(host, command, no_instance_id, ip):
  global set_debug

  if host.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(host)
  else:
    reservations = aws_search_ec2_instances_by_name(host)

  if not reservations:
    reservations = aws_search_ec2_instances_by_name('*'+host+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      if instance['State']['Name']=='running':
        if not no_instance_id:
          print("{: <60} {}".format(ec2_get_instance_name(instance), instance['InstanceId']))
        try:
          subprocess.check_call(['ssh', user_to_ssh+'@'+ec2_get_ip(instance, ip), command])
        except Exception as e:
          if set_debug:
            print(str(e))

@ec2.command()
@click.argument('host')
@click.argument('file')
@click.argument('target', default='~')
@click.option('--no-instance-id', is_flag=True, default=False, help='connect to any host that matches')
@click.option('--ip', default=None, help='IP to use for ssh')
def scp(host, file, target,no_instance_id):
  global set_debug

  if host.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(host)
  else:
    reservations = aws_search_ec2_instances_by_name(host)

  if not reservations:
    reservations = aws_search_ec2_instances_by_name('*'+host+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      if instance['State']['Name']=='running':
        if not no_instance_id:
          print("{: <60} {}".format(ec2_get_instance_name(instance), instance['InstanceId']))
        try:
          subprocess.check_call(['scp', file, user_to_ssh+'@'+ec2_get_ip(instance, ip)+':'+target])
        except Exception as e:
          if set_debug:
            print(str(e))

@ec2.command()
@click.argument('name')
@click.option('--sure', is_flag=True, default=False, help='shut up BITCH! I known what I\'m doing')
def start(name, sure):
  global set_debug, ec2_client

  if not ec2_client:
    init_ec2_client()

  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name(name)
  
  if not reservations:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      if instance['State']['Name']=='stopped':
        if sure:
          try:
            ec2_start_instances_response = ec2_client.start_instances(InstanceIds=[instance["InstanceId"]])             
            start_id = ec2_start_instances_response['ResponseMetadata']['RequestId']
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "terminating: "+str(start_id))
          except Exception as e:
            start_exception = str(e)
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "error terminating: "+str(start_exception))
        else:
          print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], instance['State']['Name']+" (use --sure to start)")


@ec2.command()
@click.argument('name')
@click.option('--sure', is_flag=True, default=False, help='shut up BITCH! I known what I\'m doing')
def stop(name, sure):
  global set_debug, ec2_client

  if not ec2_client:
    init_ec2_client()

  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name(name)
  
  if not reservations:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      if instance['State']['Name']=='running':
        if sure:
          try:
            ec2_stop_instances_response = ec2_client.stop_instances(InstanceIds=[instance["InstanceId"]])             
            stop_id = ec2_stop_instances_response['ResponseMetadata']['RequestId']
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "terminating: "+str(stop_id))
          except Exception as e:
            stop_exception = str(e)
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "error terminating: "+str(stop_exception))
        else:
          print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], instance['State']['Name']+" (use --sure to stop)")


@ec2.command()
@click.argument('name')
@click.option('--sure', is_flag=True, default=False, help='shut up BITCH! I known what I\'m doing')
def terminate(name, sure):
  global set_debug, ec2_client

  if not ec2_client:
    init_ec2_client()

  if name.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(name)
  else:
    reservations = aws_search_ec2_instances_by_name(name)
  
  if not reservations:
    reservations = aws_search_ec2_instances_by_name('*'+name+'*')

  for reservation in reservations:
    for instance in reservation["Instances"]:
      if instance['State']['Name']!='terminated':
        if sure:
          try:
            ec2_terminate_instances_response = ec2_client.terminate_instances(InstanceIds=[instance["InstanceId"]])             
            termination_id = ec2_terminate_instances_response['ResponseMetadata']['RequestId']
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "terminating: "+str(termination_id))
          except Exception as e:
            termination_response = str(e)
            print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], "error terminating: "+str(termination_response))
        else:
          print_instance(ec2_get_instance_name(instance), ec2_get_ip(instance), instance['InstanceId'], instance['LaunchTime'], instance['KeyName'], instance['State']['Name']+" (use --sure to terminate)")

def ec2_ami_describe(ami):
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  response = ec2_client.describe_images(ImageIds=[ami])

  try:
    return response['Images'][0]
  except:
    return None

@ec2.group()
def ami():
  """ EC2 AMI related commands """
  pass

@ami.command()
@click.argument('instance-id')
@click.argument('ami-name')
@click.option('--reboot', is_flag=True, default=False, help='create AMI rebooting instance')
@click.option('--description',  default=None, help='AMI description')
def create_image(instance_id, ami_name, reboot, description):
  """ create an AMI from an instance """
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  if not description:
    description = "AMI created from instance "+instance_id

  response = ec2_client.create_image(InstanceId=instance_id, Name=ami_name, NoReboot=not reboot, Description=description)
  #print(response)
  print("AMI created: "+response['ImageId'])

@ami.command()
@click.argument('ami')
@click.option('--no-title', is_flag=True, default=False, help='don\'t show column description')
def show(ami, no_title):
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  try:
    ami = ec2_ami_describe(ami)
  except Exception as e:
    sys.exit("ERROR - "+str(e))

  if not ami:
    return
  else:
    if not no_title:
      print("{: <90} {: <25} {: <20} {: <10} {: <10} {: <15} {}".format("Name", "ImageId", "Owner", "Public", "Arch", "Platform", "State"))

    print("{: <90} {: <25} {: <20} {: <10} {: <10} {: <15} {}".format(ami['Name'], ami['ImageId'], ami['OwnerId'], ami['Public'], ami['Architecture'], ami['PlatformDetails'], ami['State']))

@ami.command()
@click.argument('ami')
def launch_permissions(ami):
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  try:
    response = ec2_client.describe_image_attribute(
                            Attribute='launchPermission',
                            ImageId=ami,
                            DryRun=False
                          )   
    ami = ec2_ami_describe(ami)
  except Exception as e:
    sys.exit("ERROR - "+str(e))

  if not ami:
    return
  else:
    print("{: <15} {}".format('Owner', ami['OwnerId']))

  for launchpermission in response['LaunchPermissions']:
    if 'UserId' in launchpermission.keys():
      print("{: <15} {}".format('UserId', launchpermission['UserId']))
    if 'Group' in launchpermission.keys():
      print("{: <15} {}".format('Group', launchpermission['Group']))

@ami.command()
@click.argument('ami')
@click.option('--account',  multiple=True, default=[], help='Add account to LaunchPermissions')
def add_launchpermissions(ami, account):
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

@ec2.command()
@click.argument('instance_id')
def instance_tags(instance_id,):
  """show instance tags"""
  global set_debug

  if instance_id.startswith('i-'):
    reservations = aws_search_ec2_instances_by_id(instance_id)

    try:
      tags = reservations[0]['Instances'][0]['Tags']
      get_key_value = lambda obj: obj['Key']
      for tag in sorted(tags, key=get_key_value, reverse=False):
        print("{: <60} = {}".format(tag['Key'], tag['Value']))
    except:
      print("Error retrieving tags")
  else:
    print("please use instance-id")

@ec2.command()
@click.argument('name', required=False, default=None)
def subnet(name):
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  if name:
    filter = [{'Name': 'tag:Name', 'Values': ["*"+name+"*"]}]
  else:
    filter = []

  response = ec2_client.describe_subnets(
                      Filters=filter
                    )

  if response['Subnets']:
    for subnet in response['Subnets']:
      subnet_name = ''
      try:
        for tag in subnet['Tags']:
          if tag['Key'] == 'Name':
            subnet_name = tag['Value']
      except:
        pass
      print("{: <30} {: <30} {: <30} {: <30} {: <30} {: <30} {}".format(subnet_name, subnet['SubnetId'], subnet['VpcId'], subnet['AvailabilityZone'], subnet['CidrBlock'], subnet['State'], subnet['AvailableIpAddressCount']))


#
# EC2 ASG
#

autoscaling_client = None

def init_autoscaling_client():
  global autoscaling_client

  try:
    if set_region:
      autoscaling_client = boto3.client(service_name='autoscaling', region_name=set_region)
    else:
      autoscaling_client = boto3.client(service_name='autoscaling')
  except Exception as e:
    sys.exit('ERROR: '+str(e))

def aws_search_ec2_asg_by_name(name):
  global autoscaling_client
  max_items = 50
  records = []

  if not autoscaling_client:
    init_autoscaling_client()

  batch = autoscaling_client.describe_auto_scaling_groups(MaxRecords=max_items)
  
  for asg in batch['AutoScalingGroups']:
    if name in asg['AutoScalingGroupName']:
      records.append(asg)
  while 'NextToken' in batch.keys():
    batch = autoscaling_client.describe_auto_scaling_groups(MaxRecords=max_items, NextToken=batch['NextToken'])

    for asg in batch['AutoScalingGroups']:
      if name in asg['AutoScalingGroupName']:
        records.append(asg)
  return records

def aws_set_capacity_ec2_asg_by_name(name, max_size, min_size, capacity, honor_cooldown):
  global autoscaling_client

  if not autoscaling_client:
    init_autoscaling_client()

  try:
    response = autoscaling_client.update_auto_scaling_group(
                            AutoScalingGroupName=name,
                            MinSize=min_size,
                            MaxSize=max_size,
                          )

    if response['ResponseMetadata']['HTTPStatusCode']!=200:
      return "ERROR update_auto_scaling_group: "+str(response['ResponseMetadata']['HTTPStatusCode'])

    response = autoscaling_client.set_desired_capacity(
                        AutoScalingGroupName=name,
                        DesiredCapacity=capacity,
                        HonorCooldown=honor_cooldown
                      )

    if response['ResponseMetadata']['HTTPStatusCode']!=200:
      return "ERROR set_desired_capacity: "+str(response['ResponseMetadata']['HTTPStatusCode'])

  except Exception as e:
    return str(e)
  
  return "updated capacity"

def aws_asg_instance_refresh_by_name(name):
  global autoscaling_client

  if not autoscaling_client:
    init_autoscaling_client()

  try:
    response = autoscaling_client.start_instance_refresh(AutoScalingGroupName=name)

    return response['InstanceRefreshId']

  except Exception as e:
    return str(e)

@ec2.group()
def asg():
  """ EC2 ASG related commands """
  pass

@asg.command()
@click.argument('name', default='')
@click.option('--no-title', is_flag=True, default=False, help='don\'t show column description')
def list(name, no_title):
  if not no_title:
    print("{: <60} {: >20} {: >20} {: >20} {: >20}".format("AutoScalingGroupName", "DesiredCapacity", "MinSize", "MaxSize", "InstanceCount"))

  for asg in aws_search_ec2_asg_by_name(name):
    # print(str(asg))
    print("{: <60} {: >20} {: >20} {: >20} {: >20}".format(asg['AutoScalingGroupName'], asg['DesiredCapacity'], asg['MinSize'], asg['MaxSize'], len(asg['Instances']) ))

@asg.command()
@click.argument('name', default='')
def suspended_processes(name):
  for asg in aws_search_ec2_asg_by_name(name):
    list_sp = []
    for sp in asg['SuspendedProcesses']:
      list_sp.append(sp['ProcessName'])
    print("{: <80} {}".format(asg['AutoScalingGroupName'], " ".join(list_sp)) )

# filter non-relevant?
@asg.command()
@click.argument('name')
@click.option('--no-title', is_flag=True, default=False, help='don\'t show column description')
def list_instance_refreshes(name, no_title):
  global autoscaling_client

  records = aws_search_ec2_asg_by_name(name)

  output_format = "{: <40} {: <40} {: <20} {: <27} {: <27} {: >20} {}"

  if not records:
    sys.exit('ERROR: ASGs not found')

  if not autoscaling_client:
    init_autoscaling_client()

  if not no_title:
    print(output_format.format("AutoScalingGroupName", "InstanceRefreshId", "Status", "StartTime", "EndTime", 'InstancesToUpdate', 'StatusReason'))

  for asg in records:
    response = autoscaling_client.describe_instance_refreshes(AutoScalingGroupName=asg['AutoScalingGroupName'])    

    for refresh in response['InstanceRefreshes']:
      try:
        start_time = str(refresh['StartTime'])
      except:
        start_time = ""

      try:
        end_time = str(refresh['EndTime'])
      except:
        end_time = ""

      try:
        status = refresh['Status']
      except:
        status = ""

      try:
        status_reason = refresh['StatusReason']
      except:
        status_reason = ""

      try:
        instances_to_update = str(refresh['InstancesToUpdate'])
      except:
        instances_to_update = ""

      try:
        print(output_format.format(asg['AutoScalingGroupName'], refresh['InstanceRefreshId'], status, start_time, end_time, instances_to_update, status_reason) )
      except:
        print(output_format.format(asg['AutoScalingGroupName'], '-', '-', '-', '-', '-', '-') )



@asg.command()
@click.argument('name')
def start_instance_refresh(name):
  records = aws_search_ec2_asg_by_name(name)

  if not records:
    sys.exit('ERROR: ASGs not found')

  for asg in records:
    response = aws_asg_instance_refresh_by_name(asg['AutoScalingGroupName'])

    print("{: <60} {}".format(asg['AutoScalingGroupName'], str(response)) )

@asg.command()
@click.argument('name')
@click.option('--instance', default=[], multiple=True)
@click.option('--decrement_asg', default=False, is_flag=True, help='decrement ASG capacity')
def detach_instances(name, instance, decrement_asg):

  if not autoscaling_client:
    init_autoscaling_client()

  list_asg = aws_search_ec2_asg_by_name(name)

  if not list_asg:
    sys.exit('ERROR: ASGs not found')

  # print("list asg {} list instances {}".format(len(list_asg), len(instance)))

  for asg in list_asg:
    # print(str(asg))
    instance_ids = []
    try:
      for i in asg['Instances']:
        instance_ids.append(i['InstanceId'])
    except:
      pass

    if len(instance)>0:
      for i in instance:
        if i in instance_ids:
          # detach instance
          response = autoscaling_client.detach_instances(
                              InstanceIds=[i],
                              AutoScalingGroupName=asg['AutoScalingGroupName'],
                              ShouldDecrementDesiredCapacity=decrement_asg
                            )
          print("detaching {} from {}: {}".format(i, asg['AutoScalingGroupName'], str(response['ResponseMetadata']['RequestId'])))
    else:
      # detach all instances
      response = autoscaling_client.detach_instances(
                          InstanceIds=instance_ids,
                          AutoScalingGroupName=asg['AutoScalingGroupName'],
                          ShouldDecrementDesiredCapacity=decrement_asg
                        )
      print("detaching all instances ({}) from {} - {}".format(
                                    " ".join(instance_ids), 
                                    asg['AutoScalingGroupName'], 
                                    str(response['ResponseMetadata']['RequestId']))
                                  )

@asg.command()
@click.argument('name')
@click.argument('capacity', type=int)
@click.option('--max-size', default=-1, help='ASG max size', type=int)
@click.option('--min-size', default=-1, help='ASG min size', type=int)
@click.option('--honor-cooldown', is_flag=True, default=False, help='honor cooldown')
@click.option('--terminate', is_flag=True, default=False, help='terminate instances')
def set_capacity(name, capacity, max_size, min_size, honor_cooldown, terminate):

  records = aws_search_ec2_asg_by_name(name)

  if not records:
    sys.exit('ERROR: ASGs not found')

  if max_size < 0:
    set_max_size = capacity
  else:
    set_max_size = max_size

  if min_size < 0:
    set_min_size = capacity
  else:
    set_min_size = min_size

  for asg in records:
    response = aws_set_capacity_ec2_asg_by_name(asg['AutoScalingGroupName'], set_max_size, set_min_size, capacity, honor_cooldown)

    if terminate and capacity==0:
      instances_to_terminate = []

      for instance in asg['Instances']:
        instances_to_terminate.append(instance['InstanceId'])
      
      if instances_to_terminate:
        try:
          termination_response = aws_ec2_terminate_instances_by_id(instances_to_terminate)
        except Exception as e:
          termination_response['ResponseMetadata']['RequestId'] = e
        print("{: <60} {: <30} {}".format(asg['AutoScalingGroupName'], str(response), str(termination_response['ResponseMetadata']['RequestId'])) )
      else:
        print("{: <60} {}".format(asg['AutoScalingGroupName'], str(response)) )    
    else:
      print("{: <60} {}".format(asg['AutoScalingGroupName'], str(response)) )

#
# EC2 SG
#

@ec2.group()
def sg():
  """ EC2 SG related commands """
  pass


@sg.command()
@click.argument('name')
def list(name):
  """ list SGs"""
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  paginator = ec2_client.get_paginator('describe_security_groups')
  dsg_iterator = paginator.paginate()

  for page in dsg_iterator:
    for sg in page['SecurityGroups']:
      if name in sg['GroupName'] or name == sg['GroupId']:
        # print(str(sg))
        print("{: <40} {: <30} {}".format(sg['GroupName'], sg['GroupId'], sg['Description']) )

@sg.command()
@click.argument('name')
def delete_entangled(name):
  """ delete entangled SGs"""
  global ec2_client

  if not ec2_client:
    init_ec2_client()

  paginator = ec2_client.get_paginator('describe_security_groups')
  dsg_iterator = paginator.paginate()

  for page in dsg_iterator:
    for sg in page['SecurityGroups']:
      if name in sg['GroupName'] or name == sg['GroupId']:
        response_in = ec2_client.revoke_security_group_ingress(SourceSecurityGroupName=sg['GroupName'], IpPermissions=sg['IpPermissions'])
        response_e = ec2_client.revoke_security_group_egress(SourceSecurityGroupName=sg['GroupName'], IpPermissions=sg['IpPermissionsEgress'])
        response_sg = ec2_client.delete_security_group(GroupId=sg['GroupId'])
        print("{: <40} {: <30} {: <10} {: <10} {}".format(sg['GroupName'], sg['GroupId'], response_in['Return'], response_e['Return'], response_sg['ResponseMetadata']['RequestId']) )

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
  """ Route53 related commands """
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
@click.argument('record-name')
def delete_record(zone_id, record_name):
  """delete DNS record from hosted zone"""
  global route53_client

  if not route53_client:
    init_route53_client()

  if not aws_route53_zone_exists(zone_id):
    sys.exit('zone '+zone_id+' not found')

  record_to_delete = None
  response = route53_client.list_resource_record_sets(HostedZoneId=zone_id, StartRecordName=record_name, MaxItems='1')

  # print('deleting: ' + record_name)
  if record_name in response['ResourceRecordSets'][0]['Name']:
      record_to_delete = response['ResourceRecordSets'][0]
      route53_client.change_resource_record_sets(
          HostedZoneId=zone_id,
          ChangeBatch={
              'Changes': [{
                  'Action': 'DELETE',
                  'ResourceRecordSet': record_to_delete
              }]
          }
      )
      print('deleted: ' + record_to_delete['Name'])
      
  else:
      print('record not found: ' + record_name)

@route53.command()
@click.argument('zone-id')
@click.option('--include-not-importable', is_flag=True, default=False, help='include NS and SOA records')
@click.option('--exclude-domain-aws-validation', is_flag=True, default=False, help='exclude .acm-validations.aws. records')
@click.option('--domain-aws-validation', is_flag=True, default=False, help='only include .acm-validations.aws. records')
@click.option('--match-records', default="", help='select specific records', type=str)
def export_records(zone_id, include_not_importable, exclude_domain_aws_validation, domain_aws_validation, match_records):
  """export zone records to JSON"""

  if HOSTED_ZONE_PREFIX not in zone_id:
    zone_id = HOSTED_ZONE_PREFIX+zone_id

  records = aws_route53_list_resource_record_sets(zone_id)

  zone_name = aws_route53_get_zone_name(zone_id)

  if not include_not_importable:
    records_to_remove = []
    for record in records:
      if (record['Name']==zone_name and record['Type']=='NS') or (record['Name']==zone_name and record['Type']=='SOA'):
        records_to_remove.append(record)
    for record in records_to_remove:
      records.remove(record)

  if match_records:
    records_to_remove = []
    for record in records:
      if match_records not in record['Name']:
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

  if HOSTED_ZONE_PREFIX not in zone_id:
    zone_id = HOSTED_ZONE_PREFIX+zone_id

  if tr and tr[-1]!='.':
    tr+='.'

  if tr_hz and HOSTED_ZONE_PREFIX in tr_hz:
    tr_hz = tr_hz.lstrip(HOSTED_ZONE_PREFIX)

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
          record['AliasTarget']['HostedZoneId']=zone_id.lstrip(HOSTED_ZONE_PREFIX)
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

  response = route53_client.change_resource_record_sets(ChangeBatch=changebatch, HostedZoneId=zone_id.lstrip(HOSTED_ZONE_PREFIX))

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
  """ EKS related commands """
  pass

@eks.command()
@click.argument('cluster')
@click.option('--kubeconfig', default='', help='kubeconfig file', type=str)
def update_kubeconfig(cluster, kubeconfig):
  """import EKS cluster context to kubectl"""
  global set_debug, set_profile, set_region
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
  """ S3 utilities """
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

@s3.command()
@click.argument('bucket')
@click.option('--sure', is_flag=True, default=False, help='shut up BITCH! I known what I\'m doing')
def delete(bucket, sure):
  """ delete bucket """
  global s3_client

  if not s3_client:
    init_s3_client()
  
  if not sure:
    sys.exit("Are you sure you want to delete "+bucket+"? (--sure)")
  else:
    try:
      response = s3_client.delete_bucket(Bucket=bucket)
      print(str(response['ResponseMetadata']['RequestId']))
    except Exception as e:
      sys.exit('Unable to delete bucket '+bucket+': '+str(e))

@s3.command()
@click.argument('bucket')
@click.option('--sure', is_flag=True, default=False, help='shut up BITCH! I known what I\'m doing')
@click.option('--delete', is_flag=True, default=False, help='delete bucket')
def purge(bucket, sure, delete):
  """delete all objects and versions"""
  global s3_client

  if sure:
    if not s3_client:
      init_s3_client()

    batch = s3_client.list_object_versions(MaxKeys=1000, Bucket=bucket)
    str_out = "{: <20} {: <20} {}"
    
    iteration = 0
    while True:

      objects_to_delete = []

      if 'Versions' in batch.keys():
        for version in batch['Versions']:
          delete_candidate = {}
          delete_candidate['Key'] = version['Key']
          delete_candidate['VersionId'] = version['VersionId']

          objects_to_delete.append(delete_candidate)
      if 'DeleteMarkers' in batch.keys():
        for version in batch['DeleteMarkers']:
          delete_candidate = {}
          delete_candidate['Key'] = version['Key']
          delete_candidate['VersionId'] = version['VersionId']

          objects_to_delete.append(delete_candidate)
      
      if len(objects_to_delete) == 0:
        print("No objects to delete")
        break

      if iteration == 0:
        print(str_out.format('Requested', 'Deleted', 'Errors'))

      response = s3_client.delete_objects(
                        Bucket=bucket,
                        Delete={
                          'Objects': objects_to_delete
                        },
                        )
      try:
        delete_deleted = len(response['Deleted'])
      except:
        delete_deleted = 0
      try:
        delete_errors = len(response['Errors'])
      except:
        delete_errors = 0
      print(str_out.format(len(objects_to_delete), delete_deleted, delete_errors))


      try:
        batch = s3_client.list_object_versions(
                        MaxKeys=1000, 
                        Bucket=bucket,
                        KeyMarker=batch['NextKeyMarker']
                        )
        if not batch['IsTruncated']:
          break
      except:
        break

      iteration += 1
    
    if delete:
      try:
        response = s3_client.delete_bucket(Bucket=bucket)
        print("deleting bucket "+bucket+" "+str(response['ResponseMetadata']['RequestId']))
      except Exception as e:
        sys.exit('Unable to delete bucket '+bucket+': '+str(e))
  else:
    if delete:
      sys.exit("Are you sure you want the bucket "+bucket+" and all it's contents? (--sure)")
    else:
      sys.exit("Are you sure you want to all objects and versions from "+bucket+"? (--sure)")

#
# SM SecretsManager
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
  """ SM SecretManager related commands """
  pass

@sm.command()
def list():
  """list secrets"""

  secrets = aws_secretsmanager_list()

  for secret in secrets:
    print("{: <60} {: <15} {}".format(secret['Name'], secret['ARN'], secret.get('Description', '')))

@sm.command()
@click.argument('name')
def search(name):
  """search secrets"""

  secrets = aws_secretsmanager_list()

  for secret in secrets:
    if name in secret['Name']:
      print("{: <45} {: <110} {: <15}".format(secret['Name'], secret['ARN'], secret.get('Description', '')))

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
  """ SSM Systems Manager related commands """
  pass

@ssm.command()
def list():
  """list parameters"""

  for parameter in aws_ssm_list_parameters():
    if 'Description' in parameter.keys():
      print("{: <60} {: <15} {: <15} {: <80} {}".format(parameter['Name'], parameter['Type'], parameter['KeyId'], parameter['Description'], str(parameter['LastModifiedDate'])))
    else:
      print("{: <60} {: <15} {: <15} {: <80} {}".format(parameter['Name'], parameter['Type'], parameter['KeyId'], '', str(parameter['LastModifiedDate'])))

@ssm.command()
@click.argument('parameter')
@click.option('--output-json', is_flag=True, default=False, help='output as JSON')
@click.option('--output-k8s-secret', is_flag=True, default=False, help='output as JSON')
@click.option('--k8s-secret-name',  default=None, help='Rename parameter to')
def get(parameter, output_json, output_k8s_secret, k8s_secret_name):
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
    elif output_k8s_secret:
      value_b64 = base64.b64encode(parameter_json['Value'].encode('utf-8')).decode('utf-8')

      if not k8s_secret_name:
        k8s_secret_name = re.sub('^-', '', parameter_json['Name'].replace('/', '-'))

      print('apiVersion: v1')
      print('data:')
      print('  {}: {}'.format(k8s_secret_name, value_b64))
      print('kind: Secret')
      print('metadata:')
      print('  name: "{}"'.format(k8s_secret_name))
      print('type: Opaque')
    else:
      print("{: <50} {: <30} {: <15} {}".format(parameter_json['Name'], parameter_json['Value'], parameter_json['Type'], parameter_json['ARN']))
  except Exception as e:
    sys.exit('Parameter not found: '+str(e))

@ssm.command()
@click.option('--import-file',  help='file to read json data from', type=click.File('r'), default=sys.stdin)
@click.option('--rename',  default=None, help='Rename parameter to')
@click.option('--overwrite', is_flag=True, default=False, help='overwrite parameter')
@click.option('--key',  default="alias/aws/ssm", help='KMS Key to use')
def put(import_file, rename, overwrite, key):
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
                KeyId=key,
                Overwrite=overwrite,
              )

  print(str(response['ResponseMetadata']['RequestId']))

@ssm.command()
@click.argument('parameter')
@click.argument('value')
@click.option('--description', default='', help='parameter description', type=str)
@click.option('--overwrite', is_flag=True, default=False, help='overwrite parameter')
@click.option('--key',  default="alias/aws/ssm", help='KMS Key to use')
def set(parameter, value, description, overwrite, key):
  """set SecureString parameter"""
  if not ssm_client:
    init_ssm_client()

  response = ssm_client.put_parameter(
                Name=parameter,
                Value=value,
                Description=description,
                Type='SecureString',
                KeyId=key,
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
  """ KMS related commands """
  pass

@kms.command()
def list():
  """list keys"""
  for key in aws_kms_list():
    
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

def acm_describe_cert(cert):
  global acm_client

  if not acm_client:
    init_acm_client()

  return acm_client.describe_certificate(CertificateArn=cert['CertificateArn'])['Certificate']

def aws_acm_list():
  global acm_client

  max_items = 1000

  if not acm_client:
    init_acm_client()

  records = []

  batch = acm_client.list_certificates(MaxItems=max_items)

  for each_cert in batch['CertificateSummaryList']:
    records.append(acm_describe_cert(each_cert))

  while 'NextToken' in batch.keys():
    batch = acm_client.list_certificates(
                    MaxItems=max_items,
                    NextToken=batch['NextToken']
                  )

    for each_cert in batch['CertificateSummaryList']:
      records.append(acm_describe_cert(each_cert))

  return records

@awstools.group()
def acm():
  """ ACM related commands """
  pass

@acm.command()
def list():
  """list certificates"""

  certs = aws_acm_list()

  for cert in certs:
    # print(str(cert))
    print("{: <100} {}".format(cert['CertificateArn'], cert['DomainName']))

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


def aws_acm_list_db_instances(name=None):
  global rds_client

  max_items = 100
  records = []

  if not rds_client:
    init_rds_client()

  batch = rds_client.describe_db_instances(MaxRecords=max_items)
  for db in batch['DBInstances']:
    if name in db['DBInstanceIdentifier']:
      records.append(db)
  while 'Marker' in batch.keys():
    batch = rds_client.describe_db_instances(
                    MaxRecords=max_items,
                    Marker=batch['Marker']
                  )

    for db in batch['DBInstances']:
      if name in db['DBInstanceIdentifier']:
        records.append(db)

  return records

@awstools.group()
def rds():
  """ RDS related commands """
  pass

@rds.command()
@click.argument('name', default='', type=str)
def list(name):
  """list dbs instances"""

  dbinstances = aws_acm_list_db_instances(name)

  for dbinstance in dbinstances:
    # print(str(dbinstance))
    print("{: <50} {: <20} {: <20} {}".format(dbinstance['DBInstanceIdentifier'], dbinstance['Engine'], dbinstance['DBInstanceStatus'], str(dbinstance['DBParameterGroups'])))

@rds.group()
def snapshots():
  """ RDS snapshots related commands """
  pass

@snapshots.command()
@click.argument('dbinstance', type=str)
@click.argument('snapshotname', type=str)
def create(dbinstance, snapshotname):
  global rds_client

  if not rds_client:
    init_rds_client()

  response = rds_client.create_db_snapshot(
                        DBSnapshotIdentifier=snapshotname,
                        DBInstanceIdentifier=dbinstance,
                      )
  print('HTTP '+str(response['ResponseMetadata']['HTTPStatusCode'])+' '+response['ResponseMetadata']['RequestId'])
  
@snapshots.command()
@click.argument('dbname', type=str)
def show(dbname):
  global rds_client

  if not rds_client:
    init_rds_client()

  response = rds_client.describe_db_snapshots(DBInstanceIdentifier=dbname)
  
  for snapshot  in response['DBSnapshots']:
    print("{: <50} {}".format(snapshot['DBSnapshotIdentifier'], snapshot['Status']))

#
# elasticache
#

elasticache_client = None

def init_elasticache_client():
  global elasticache_client

  try:
    if set_region:
      elasticache_client = boto3.client(service_name='elasticache', region_name=set_region)
    else:
      elasticache_client = boto3.client(service_name='elasticache')
  except Exception as e:
    sys.exit('ERROR: '+str(e))

def aws_elasticache_list_cluster_instances(name=None, nodeinfo=False):
  global elasticache_client

  max_items = 100
  records = []

  if not elasticache_client:
    init_elasticache_client()

  batch = elasticache_client.describe_cache_clusters(MaxRecords=max_items, ShowCacheNodeInfo=nodeinfo)
  for db in batch['CacheClusters']:
    if name in db['CacheClusterId']:
      records.append(db)
  while 'Marker' in batch.keys():
    batch = rds_client.describe_db_instances(
                    MaxRecords=max_items,
                    ShowCacheNodeInfo=nodeinfo,
                    Marker=batch['Marker']
                  )

    for db in batch['CacheClusters']:
      if name in db['CacheClusterId']:
        records.append(db)

  return records

@awstools.group()
def elasticache():
  """ elasticache related commands """
  pass

@elasticache.command()
@click.argument('name', default='', type=str)
def list(name):
  """list elasticache clusters"""

  instances = aws_elasticache_list_cluster_instances(name)

  for instance in instances:
    print("{: <50} {: <20} {: <20} {}".format(instance['CacheClusterId'], instance['Engine'], instance['CacheClusterStatus'], str(instance['NumCacheNodes'])))


@elasticache.command()
@click.argument('name', default='', type=str)
def reboot(name):
  """reboot elasticache clusters"""
  global elasticache_client

  if not elasticache_client:
    init_elasticache_client()

  instances = aws_elasticache_list_cluster_instances(name=name, nodeinfo=True)

  for instance in instances:
    nodes = []
    if instance['CacheClusterStatus'] in ['available', 'incompatible-parameters', 'snapshotting']:
      for cachenode in instance['CacheNodes']:
        nodes.append(cachenode['CacheNodeId'])
      response = elasticache_client.reboot_cache_cluster(
                          CacheClusterId=instance['CacheClusterId'],
                          CacheNodeIdsToReboot=nodes
                        )
      print("{: <50} {}".format(instance['CacheClusterId'], response['CacheCluster']['CacheClusterStatus']))
    else:
      print("{: <50} {}".format(instance['CacheClusterId'], "unable to reboot; current status is: "+instance['CacheClusterStatus']))


if __name__ == '__main__':
  load_defaults(os.path.join(os.getenv("HOME"), '.awstools/config'))
  awstools()
