import logging
import boto3
from argparse import ArgumentParser, HelpFormatter
from botocore.exceptions import ClientError, ProfileNotFound

# from botocore.errorfactory import UnauthorizedException

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')

# Argument parser config
formatter = lambda prog: HelpFormatter(prog, max_help_position=52)
parser = ArgumentParser(formatter_class=formatter)
# parser = ArgumentParser()
parser.add_argument("-v", "--vpc", required=True, help="The VPC to annihilate")
parser.add_argument("-r", "--region", default="us-east-1", help="AWS region that the VPC resides in")
parser.add_argument("-d", "--dryrun", action='store_true', help="If exists, dry run all deletions.")
parser.add_argument("-p", '--profile', default='default', help="AWS profile")
args = parser.parse_args()

# boto client config
try:
    session = boto3.Session(profile_name=args.profile)
except ProfileNotFound as e:
    logger.warning("{}, please provide a valid AWS profile name".format(e))
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
dry_run: bool = args.dryrun


def vpc_in_region():
    """
    Describes one or more of your VPCs.
    """
    vpc_exists = False
    try:
        vpcs = list(ec2.vpcs.filter(Filters=[]))
    except ClientError as e:
        logger.warning(e.response['Error']['Message'])
        exit()
    logger.info("VPCs in region {}:".format(args.region))
    for vpc in vpcs:
        logger.info(vpc.id)
        if vpc.id == vpc_id:
            vpc_exists = True

    logger.info("--------------------------------------------")
    return vpc_exists


def delete_asgs():
    logger.info("ASGs in VPC {}:".format(vpc_id))
    asgs = asg_client.describe_auto_scaling_groups()['AutoScalingGroups']
    for asg in asgs:
        asg_name = asg['AutoScalingGroupName']

        if asg_in_vpc(asg):
            logger.info("Deleting {}".format(asg_name))
            if dry_run:
                logger.info("DryRun flag is set, skipping {}...".format(asg_name))
                continue
            asg_client.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)

    logger.info("--------------------------------------------")
    return


def asg_in_vpc(asg):
    subnets_list = asg['VPCZoneIdentifier'].split(',')
    for subnet in subnets_list:
        try:
            sub_description = vpc_client.describe_subnets(SubnetIds=[subnet])['Subnets']
            if sub_description[0]['VpcId'] == vpc_id:
                logger.info("{} resides in {}".format(asg['AutoScalingGroupName'], vpc_id))
                return True
        except ClientError as e:
            # logger.warning(e.response['Error']['Message'])
            pass

    return False


def delete_ekss():
    waiter = eks_client.get_waiter('cluster_deleted')
    ekss = eks_client.list_clusters()['clusters']

    logger.info("EKSs in VPC {}:".format(vpc_id))
    for eks in ekss:
        eks_desc = eks_client.describe_cluster(name=eks)['cluster']
        if eks_desc['resourcesVpcConfig']['vpcId'] == vpc_id:
            logger.info("Deleting {}...".format(eks_desc['name']))
            try:
                eks_client.delete_cluster(name=eks_desc['name'])
                waiter.wait(name=eks_desc['name'], DryRun=dry_run)
            except ClientError as e:
                logger.warning(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_ec2s():
    waiter = vpc_client.get_waiter('instance_terminated')
    reservations = vpc_client.describe_instances(Filters=[{"Name": "vpc-id",
                                                           "Values": [vpc_id]}])['Reservations']

    # Get a list of ec2s
    ec2s = [ec2['InstanceId'] for reservation in reservations for ec2 in reservation['Instances']]

    logger.info("EC2s in VPC {}:".format(vpc_id))
    for ec2 in ec2s:
        logger.info("Deleting {}...".format(ec2))
        try:

            vpc_client.terminate_instances(InstanceIds=[ec2], DryRun=dry_run)
            waiter.wait(InstanceIds=[ec2], DryRun=dry_run)

        except ClientError as e:
            logger.warning(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_lambdas():
    lmbds = lambda_client.list_functions()['Functions']

    # lmbds_list = []
    # for lmbd in lmbds:
    #     if 'VpcConfig' in lmbd:
    #         if lmbd['VpcConfig']['VpcId'] == vpc_id:
    #             lmbds_list.append(lmbd['FunctionName'])

    lambdas_list = [lmbd['FunctionName'] for lmbd in lmbds
                    if 'VpcConfig' in lmbd and lmbd['VpcConfig']['VpcId'] == vpc_id]

    logger.info("Lambdas in VPC {}:".format(vpc_id))
    for lmbda in lambdas_list:
        logger.info("Deleting {}...".format(lmbda))
        if dry_run:
            logger.info("DryRun flag is set, skipping {}...".format(lmbda))
            continue
        try:
            lambda_client.delete_function(FunctionName=lmbda)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_rdss():
    waiter = rds_client.get_waiter('db_instance_deleted')
    rdss = rds_client.describe_db_instances()['DBInstances']

    rdsss_list = [rds['DBInstanceIdentifier'] for rds in rdss if rds['DBSubnetGroup']['VpcId'] == vpc_id]

    logger.info("RDSs in VPC {}:".format(vpc_id))
    for rds in rdsss_list:
        logger.info("Deleting {}...".format(rds))
        # Did not find DryRun param for the below method
        if dry_run:
            logger.info("DryRun flag is set, skipping {}...".format(rds))
            continue
        try:
            rds_client.modify_db_instance(DBInstanceIdentifier=rds, DeletionProtection=False)
            rds_client.delete_db_instance(
                DBInstanceIdentifier=rds,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True)
            waiter.wait(DBInstanceIdentifier=rds)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_elbs():
    elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']

    elbs = [elb['LoadBalancerName'] for elb in elbs if elb['VPCId'] == vpc_id]

    logger.info("Classic ELBs in VPC {}:".format(vpc_id))
    for elb in elbs:
        logger.info("Deleting {}...".format(elb))
        # Did not find DryRun param for the below method
        if dry_run:
            logger.info("DryRun flag is set, skipping {}...".format(elb))
            continue
        try:
            elb_client.delete_load_balancer(LoadBalancerName=elb)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_elbsV2():
    elbs = elbV2_client.describe_load_balancers()['LoadBalancers']

    elbs_list = [elb['LoadBalancerArn'] for elb in elbs if elb['VpcId'] == vpc_id]

    logger.info("ELBs V2 in VPC {}:".format(vpc_id))
    for elb in elbs_list:
        logger.info("Deleting {}...".format(elb))
        # Did not find DryRun param for the below method
        if dry_run:
            logger.info("DryRun flag is set, skipping {}...".format(elb))
            continue
        try:
            elbV2_client.delete_load_balancer(LoadBalancerArn=elb)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_nats():
    nats = vpc_client.describe_nat_gateways(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['NatGateways']

    nats = [nat['NatGatewayId'] for nat in nats]
    logger.info("NAT GWs in VPC {}:".format(vpc_id))
    for nat in nats:
        try:
            logger.info("Deleting {}...".format(nat))
            vpc_client.delete_nat_gateway(NatGatewayId=nat, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_enis():
    # waiter = vpc_client.get_waiter('network_interface_available')

    # Get list of dicts
    enis = vpc_client.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])['NetworkInterfaces']
    # logger.info(json.dumps(enis, indent=2, default=str))

    # eni_attachments= []
    # for eni in enis:
    #     logger.info(eni)
    #     eni_attachments.append(eni['Attachment']['AttachmentId'])

    eni_attachments = [eni['Attachment']['AttachmentId'] for eni in enis if 'Attachment' in eni]

    # Get a list of enis
    enis = [eni['NetworkInterfaceId'] for eni in enis]

    for attachment in eni_attachments:
        try:
            logger.info("Detaching {}...".format(attachment))
            vpc_client.detach_network_interface(AttachmentId=attachment, DryRun=dry_run, Force=True)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("ENIs in VPC {}:".format(vpc_id))
    for eni in enis:
        try:
            logger.info("Disassociating {}...".format(eni))
            ec2.NetworkInterfaceAssociation(eni).delete(DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

        try:
            logger.info("Deleting {}...".format(eni))
            ec2.NetworkInterface(eni).delete(DryRun=dry_run)
            # waiter.wait(NetworkInterfaceIds=[eni], DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_igws():
    """
  Detach and delete the internet gateway
  """

    # Get list of dicts
    igws = vpc_client.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['InternetGateways']

    # logger.info(json.dumps(igws, indent=2, default=str))

    # Get a list of enis
    igws = [igw['InternetGatewayId'] for igw in igws]

    logger.info("IGWs in VPC {}:".format(vpc_id))
    for igw in igws:
        logger.info(igw)
        try:
            logger.info("Detaching...")
            vpc_client.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

        try:
            logger.info("Deleting...")
            vpc_client.delete_internet_gateway(InternetGatewayId=igw, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_vpgws():
    """
  Detach and delete the virtual private gateways
  """

    # Get list of dicts
    vpgws = vpc_client.describe_vpn_gateways(
        Filters=[{"Name": "attachment.vpc-id",
                  "Values": [vpc_id]}])['VpnGateways']

    # Get a list of enis
    vpgws = [vpgw['VpnGatewayId'] for vpgw in vpgws]

    logger.info("VPGWs in VPC {}:".format(vpc_id))
    for vpgw in vpgws:
        logger.info(vpgw)
        try:
            logger.info("Detaching...")
            vpc_client.detach_vpn_gateway(VpnGatewayId=vpgw, VpcId=vpc_id, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

        try:
            logger.info("Deleting...")
            vpc_client.delete_vpn_gateway(VpnGatewayId=vpgw, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_subnets():
    # Get list of dicts of metadata
    subnets = vpc_client.describe_subnets(Filters=[{"Name": "vpc-id",
                                                    "Values": [vpc_id]}])['Subnets']

    # Get a list of subnets
    subnets = [subnet['SubnetId'] for subnet in subnets]

    logger.info("Subnets in VPC {}:".format(vpc_id))
    for subnet in subnets:
        logger.info("Deleting {}...".format(subnet))
        try:
            vpc_client.delete_subnet(SubnetId=subnet, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_acls():
    acls = vpc_client.describe_network_acls(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['NetworkAcls']

    # Get a list of subnets
    acls = [acl['NetworkAclId'] for acl in acls]
    logger.info("ACLs in VPC {}:".format(vpc_id))
    for acl in acls:
        try:
            logger.info("Deleting {}...".format(acl))
            vpc_client.delete_network_acl(NetworkAclId=acl, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_vpc():
    """
  Delete the VPC
  """
    logger.info("Deleting {}...".format(vpc_id))
    try:
        vpc_client.delete_vpc(VpcId=vpc_id, DryRun=dry_run)
    except ClientError as e:
        logger.info(e.response['Error']['Message'])
    else:
        logger.info('VPC {} has been deleted from the {} region.'.format(vpc_id, args.region))
        return True

    logger.info("--------------------------------------------")
    return False


def delete_sgs():
    sgs = vpc_client.describe_security_groups(Filters=[{"Name": "vpc-id",
                                                        "Values": [vpc_id]}])['SecurityGroups']

    # Get a list of subnets
    # sgs = [sg['GroupId'] for sg in sgs]
    logger.info("Security Groups in VPC {}:".format(vpc_id))

    for sg in sgs:

        logger.info("Revoke egress from {}...".format(sg['GroupId']))
        try:
            ec2.SecurityGroup(sg['GroupId']).revoke_egress(IpPermissions=sg['IpPermissions'], DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

        logger.info("Revoke ingress from {}...".format(sg['GroupId']))
        try:
            ec2.SecurityGroup(sg['GroupId']).revoke_ingress(IpPermissions=sg['IpPermissions'], DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

        logger.info("Deleting {}...".format(sg['GroupId']))
        try:
            vpc_client.delete_security_group(GroupId=sg['GroupId'], DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_rtbs():
    rtbs = vpc_client.describe_route_tables(Filters=[{"Name": "vpc-id",
                                                      "Values": [vpc_id]}])['RouteTables']
    # Get a list of Routing tables
    rtbs = [rtb['RouteTableId'] for rtb in rtbs]
    logger.info("Routing tables in VPC {}:".format(vpc_id))
    for rtb in rtbs:
        try:
            logger.info("Deleting {}...".format(rtb))
            vpc_client.delete_route_table(RouteTableId=rtb, DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


def delete_vpc_epts():
    epts = vpc_client.describe_vpc_endpoints(Filters=[{"Name": "vpc-id",
                                                       "Values": [vpc_id]}])['VpcEndpoints']

    # Get a list of Routing tables
    epts = [ept['VpcEndpointId'] for ept in epts]
    logger.info("VPC EndPoints in VPC {}:".format(vpc_id))
    for ept in epts:
        try:
            logger.info("Deleting {}...".format(ept))
            vpc_client.delete_vpc_endpoints(VpcEndpointIds=[ept], DryRun=dry_run)
        except ClientError as e:
            logger.info(e.response['Error']['Message'])

    logger.info("--------------------------------------------")
    return


if __name__ == '__main__':

    if vpc_in_region():
        delete_ekss()
        delete_asgs()
        delete_rdss()
        delete_ec2s()
        delete_lambdas()
        delete_elbs()
        delete_elbsV2()
        delete_vpc_epts()
        delete_nats()
        delete_enis()
        delete_sgs()
        delete_acls()
        delete_subnets()
        delete_igws()
        delete_vpgws()
        delete_rtbs()
        delete_vpc()
    else:
        logger.info("The given VPC was not found in {}".format(args.region))
