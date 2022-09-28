#!/usr/bin/env python3

# *********************************************************************************************
# Script: vpc-inside.py
# Author: Alon Lavian
# Date: 08/07/2022
# Description: This script will describe resources inside an AWS VPC.
# Python Version: 3.8.x
#
#
# Note: 
# Requires boto3 and botocore:
# Install with: sudo pip install boto3
# Install with: sudo pip install botocore
#
# Requires requests:
# Install with: sudo pip install requests
#
# EXIT STATUS:
#     Exit codes:
#     0 = Success
#     1 = Error
#
# Usage: vpc-inside.py [-h] -v VPC [-r REGION] [-p PROFILE] [-c yes/no]
#
# optional arguments:
#  -h, --help                     show this help message and exit
#  -v VPC, --vpc VPC              The VPC to describe
#  -r REGION, --region REGION     AWS region that the VPC resides in
#  -p PROFILE, --profile PROFILE  AWS profile
#  -c yes/no, --colorize yes/no   Add Colorization to output
#
#
# Update/Mutation Log:
# Who                     | Date               | Update/Mutation
# -------------------------------------------------------------------------------------------
# Richard Knechtel        | 09/12/2022         | Added vpc-inside-requiements.txt 
#                         |                    | Added README-vpc-inside.md
#                         |                    | Reworked original .py file added comments.
#                         |                    | Added colorization option of output.
#                         |                    | Added AWS Auth scripts.
# -------------------------------------------------------------------------------------------
#
#
# *********************************************************************************************

#---------------------------------------------------------[Imports]------------------------------------------------------

import logging
import boto3

from argparse import ArgumentParser, HelpFormatter
from botocore.exceptions import ClientError, ProfileNotFound

# Custom Modules:
from modules import colorprint as cp

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

# VPC ID (Required)
# Region (Optional)
# AWS Profile (Optional)
# Colorize (Optional)

#---------------------------------------------------------[Logging Initializations]--------------------------------------------------------

# See: modules\colorprint.py used for printing color to console

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(message)s')

#--------------------------------------------------------[Parameter Initialisations]-------------------------------------------------------

# Argument parser config
formatter = lambda prog: HelpFormatter(prog, max_help_position=52)
parser = ArgumentParser(formatter_class=formatter)

parser.add_argument("-v", "--vpc", required=True, help="The VPC to describe")
parser.add_argument("-r", "--region", default="us-east-1", help="AWS region that the VPC resides in")
parser.add_argument("-p", '--profile', default='default', help="AWS profile")
parser.add_argument("-c", '--colorize', default='no', help="Colorized Output")
args = parser.parse_args()

if args.colorize == "yes":
  cp.print_fg_bright_green(f"Arguments Passed: {args}")
else:
  logger.info(f"Arguments Passed: {args}")

#---------------------------------------------------------[Boto3 Initializations]--------------------------------------------------------

# boto3 client config
try:
    # session = boto3.Session(profile_name=args.profile) # Gives Error: You are not authorized to perform this operation.
    session = boto3.Session(region_name=args.region) # This Works!
except ProfileNotFound as e:
  if args.colorize == "yes":
    cp.print_fg_bright_red(f"{e}, please provide a valid AWS profile name")
  else:
    logger.warning(f"{e}, please provide a valid AWS profile name")
    exit(-1)

vpc_client = session.client("ec2", region_name=args.region)
elbV2_client = session.client('elbv2', region_name=args.region)
elb_client = session.client('elb', region_name=args.region)
lambda_client = session.client('lambda', region_name=args.region)
eks_client = session.client('eks', region_name=args.region)
asg_client = session.client('autoscaling', region_name=args.region)
rds_client = session.client('rds', region_name=args.region)
ec2 = session.resource('ec2', region_name=args.region)

vpc_id: str = args.vpc

#---------------------------------------------------------[Class Initializations]--------------------------------------------------------

# None
  
#----------------------------------------------------------[Declarations]----------------------------------------------------------

# None

#-----------------------------------------------------------[Functions]------------------------------------------------------------

def vpc_in_region():
  """
  Describes one or more of your VPCs.
  """

  vpc_exists = False
  try:
    vpcs = list(ec2.vpcs.filter(Filters=[]))
  except ClientError as ce:
    if args.colorize == "yes":
      cp.print_fg_bright_red('vpc-inside - vpc_in_region(): The EC2 Client had an error. See the Error Code and Message for details.')
      cp.print_fg_bright_red('vpc-inside - vpc_in_region(): ClientError: vpc_in_region().')
      cp.print_fg_bright_red('Error Code: {0}'.format(ce.response['Error']['Code']))
      cp.print_fg_bright_red('Error Message: {0}'.format(ce.response['Error']['Message']))
    else:
      logger.error('Error Code: {0}'.format(ce.response['Error']['Code']))
      logger.error('Error Message: {0}'.format(ce.response['Error']['Message']))
      exit()
    
  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"VPCs in region {args.region}:")
  else:
    logger.info(f"VPCs in region {args.region}:")

  for vpc in vpcs:
    if args.colorize == "yes":
      cp.print_fg_bright_green(vpc.id)
    else:
      logger.info(vpc.id)

    if vpc.id == vpc_id:
      vpc_exists = True

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")
    
  return vpc_exists


def describe_asgs():
  """
  Describes one or more of your Auto Scaling Groups.
  """

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"ASGs in VPC {vpc_id}:")
  else:
    logger.info(f"ASGs in VPC {vpc_id}:")
    
  asgs = asg_client.describe_auto_scaling_groups()['AutoScalingGroups']
  for asg in asgs:
    asg_name = asg['AutoScalingGroupName']
    if asg_in_vpc(asg):
      if args.colorize == "yes":
        cp.print_fg_bright_green(asg_name)
      else:
        logger.info(asg_name)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")
    
    return


def asg_in_vpc(asg):
  subnets_list = asg['VPCZoneIdentifier'].split(',')
  for subnet in subnets_list:
    try:
      sub_description = vpc_client.describe_subnets(SubnetIds=[subnet])['Subnets']
      if sub_description[0]['VpcId'] == vpc_id:
        if args.colorize == "yes":
          cp.print_fg_bright_green(f"{asg['AutoScalingGroupName']} resides in {vpc_id}")
        else:
          logger.info(f"{asg['AutoScalingGroupName']} resides in {vpc_id}")
      return True
    except ClientError:
      pass

  return False


def describe_ekss():
  ekss = eks_client.list_clusters()['clusters']

  if args.colorize == "yes":
   cp.print_fg_bright_blue(f"EKSs in VPC {vpc_id}:")
  else:
    logger.info("EKSs in VPC {}:".format(vpc_id))

  for eks in ekss:
    eks_desc = eks_client.describe_cluster(name=eks)['cluster']
    if eks_desc['resourcesVpcConfig']['vpcId'] == vpc_id:
      if args.colorize == "yes":
        cp.print_fg_bright_green(eks_desc['name'])
      else:
        logger.info(eks_desc['name'])

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_ec2s():
  waiter = vpc_client.get_waiter('instance_terminated')
  reservations = vpc_client.describe_instances(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['Reservations']

  # Get a list of ec2s
  ec2s = [ec2['InstanceId'] for reservation in reservations for ec2 in reservation['Instances']]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"EC2s in VPC {vpc_id}:")
  else:
    logger.info(f"EC2s in VPC {vpc_id}:")
 
  for ec2 in ec2s:
    if args.colorize == "yes":
      cp.print_fg_bright_green(ec2)
    else:
      logger.info(ec2)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")
  
  return


def describe_lambdas():
  lmbds = lambda_client.list_functions()['Functions']

  lambdas_list = [lmbd['FunctionName'] for lmbd in lmbds
                  if 'VpcConfig' in lmbd and lmbd['VpcConfig']['VpcId'] == vpc_id]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"Lambdas in VPC {vpc_id}:")
  else:
    logger.info(f"Lambdas in VPC {vpc_id}:")

  for lmbda in lambdas_list:
    if args.colorize == "yes":
      cp.print_fg_bright_green(lmbda)
    else:
      logger.info(lmbda)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_rdss():
  rdss = rds_client.describe_db_instances()['DBInstances']

  rdsss_list = [rds['DBInstanceIdentifier'] for rds in rdss if rds['DBSubnetGroup']['VpcId'] == vpc_id]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"RDSs in VPC {vpc_id}:")
  else:
    logger.info(f"RDSs in VPC {vpc_id}:")

  for rds in rdsss_list:
    if args.colorize == "yes":
      cp.print_fg_bright_green(rds)
    else:
      logger.info(rds)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_elbs():
  elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']

  elbs = [elb['LoadBalancerName'] for elb in elbs if elb['VPCId'] == vpc_id]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"Classic ELBs in VPC {vpc_id}:")
  else:
    logger.info(f"Classic ELBs in VPC {vpc_id}:")

  for elb in elbs:
    if args.colorize == "yes":
      cp.print_fg_bright_green(elb)
    else:
      logger.info(elb)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_elbsV2():
  elbs = elbV2_client.describe_load_balancers()['LoadBalancers']

  elbs_list = [elb['LoadBalancerArn'] for elb in elbs if elb['VpcId'] == vpc_id]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"ELBs V2 in VPC {vpc_id}:")
  else:
    logger.info(f"ELBs V2 in VPC {vpc_id}:")

  for elb in elbs_list:
    if args.colorize == "yes":
      cp.print_fg_bright_green(elb)
    else:
      logger.info(elb)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_nats():
  nats = vpc_client.describe_nat_gateways(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['NatGateways']

  nats = [nat['NatGatewayId'] for nat in nats]
  
  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"NAT GWs in VPC {vpc_id}:")
  else:
    logger.info(f"NAT GWs in VPC {vpc_id}:")

  for nat in nats:
    if args.colorize == "yes":
      cp.print_fg_bright_green(nat)
    else:
      logger.info(nat)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")
  
  return


def describe_enis():
  enis = vpc_client.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['NetworkInterfaces']

  # Get a list of enis
  enis = [eni['NetworkInterfaceId'] for eni in enis]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"ENIs in VPC {vpc_id}:")
  else:
    logger.info(f"ENIs in VPC {vpc_id}:")
  
  for eni in enis:
    if args.colorize == "yes":
      cp.print_fg_bright_green(eni)
    else:
      logger.info(eni)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_igws():
  """
  Describe the internet gateway
  """

  # Get list of dicts
  igws = vpc_client.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['InternetGateways']

  igws = [igw['InternetGatewayId'] for igw in igws]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"IGWs in VPC {vpc_id}:")
  else:
    logger.info(f"IGWs in VPC {vpc_id}:")

  for igw in igws:
    if args.colorize == "yes":
      cp.print_fg_bright_green(igw)
    else:
      logger.info(igw)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")
  
  return


def describe_vpgws():
  """
  Describe the virtual private gateway
  """

  # Get list of dicts
  vpgws = vpc_client.describe_vpn_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['VpnGateways']

  vpgws = [vpgw['VpnGatewayId'] for vpgw in vpgws]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"VPGWs in VPC {vpc_id}:")
  else:
    logger.info(f"VPGWs in VPC {vpc_id}:")

  for vpgw in vpgws:
    if args.colorize == "yes":
      cp.print_fg_bright_green(vpgw)
    else:
      logger.info(vpgw)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_subnets():
  # Get list of dicts of metadata
  subnets = vpc_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['Subnets']

  # Get a list of subnets
  subnets = [subnet['SubnetId'] for subnet in subnets]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"Subnets in VPC {vpc_id}:")
  else:
    logger.info(f"Subnets in VPC {vpc_id}:")

  for subnet in subnets:
    if args.colorize == "yes":
      cp.print_fg_bright_green(subnet)
    else:
      logger.info(subnet)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_acls():
  acls = vpc_client.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['NetworkAcls']

  # Get a list of Network ACL's
  acls = [acl['NetworkAclId'] for acl in acls]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"ACLs in VPC {vpc_id}:")
  else:
    logger.info(f"ACLs in VPC {vpc_id}:")

  for acl in acls:
    if args.colorize == "yes":
      cp.print_fg_bright_green(acl)
    else:
      logger.info(acl)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_sgs():
  sgs = vpc_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['SecurityGroups']

   # sgs = [sg['GroupId'] for sg in sgs]

  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"Security Groups in VPC {vpc_id}:")
  else:
    logger.info(f"Security Groups in VPC {vpc_id}:")

  for sg in sgs:
    if args.colorize == "yes":
      cp.print_fg_bright_green(sg['GroupId'])
    else:
      logger.info(sg['GroupId'])

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_rtbs():
  rtbs = vpc_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['RouteTables']
  
  # Get a list of Routing tables
  rtbs = [rtb['RouteTableId'] for rtb in rtbs]
  
  if args.colorize == "yes":
     cp.print_fg_bright_blue(f"Routing tables in VPC {vpc_id}:")
  else:
    logger.info(f"Routing tables in VPC {vpc_id}:")

  for rtb in rtbs:
    if args.colorize == "yes":
      cp.print_fg_bright_green(rtb)
    else:
      logger.info(rtb)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return


def describe_vpc_epts():
  epts = vpc_client.describe_vpc_endpoints(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['VpcEndpoints']

  # Get a list of VPC Endpoints
  epts = [ept['VpcEndpointId'] for ept in epts]
  
  if args.colorize == "yes":
    cp.print_fg_bright_blue(f"VPC EndPoints in VPC {vpc_id}:")
  else:
    logger.info(f"VPC EndPoints in VPC {vpc_id}:")

  for ept in epts:
    if args.colorize == "yes":
      cp.print_fg_bright_green(ept)
    else:
      logger.info(ept)

  if args.colorize == "yes":
    cp.print_fg_bright_yellow("--------------------------------------------")
  else:
    logger.info("--------------------------------------------")

  return

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# ************************************
# Main Script Execution
# ************************************

# Note: Below is strickly for running from a command line call:
# Will only run if this file is called as primary file 
if __name__ == '__main__':

    if vpc_in_region():
        describe_ekss()
        describe_asgs()
        describe_rdss()
        describe_ec2s()
        describe_lambdas()
        describe_elbs()
        describe_elbsV2()
        describe_nats()
        describe_vpc_epts()
        describe_igws()
        describe_vpgws()
        describe_enis()
        describe_sgs()
        describe_rtbs()
        describe_acls()
        describe_subnets()
    else:
        if args.colorize == "yes":
          cp.print_blink(f"The given VPC was not found in {args.region}")
        else:
          logger.info(f"The given VPC was not found in {args.region}")
