import logging
from googleapiclient import discovery
from google.oauth2 import service_account

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(message)s')

scopes = ['https://www.googleapis.com/auth/compute']
sa_file = 'sa_file.json'

credentials = service_account.Credentials.from_service_account_file(sa_file, scopes=scopes)

compute_service = discovery.build('compute', 'v1', credentials=credentials)

project = 'alon-lavian'
zones_list = []
network = {'name': 'alon-test-network', 'selfLink': ''}
regions_list = []


def helper_describe_regions():
    """
    Create the region list in the project
    :return:
    """
    global regions_list

    request = compute_service.regions().list(project=project)
    while request is not None:
        response = request.execute()

        for region in response['items']:
            regions_list.append(region['name'])

        request = compute_service.regions().list_next(previous_request=request, previous_response=response)

    return


def helper_describe_zones():
    """
    Create the zones list in the project
    :return:
    """
    global zones_list

    request = compute_service.zones().list(project=project)
    while request is not None:
        response = request.execute()

        for zone in response['items']:
            zones_list.append(zone['name'])

        request = compute_service.zones().list_next(previous_request=request, previous_response=response)
    return

def describe_subnetworks():
    for region in regions_list:

        request = compute_service.subnetworks().list(project=project, region=region)
        while request is not None:
            response = request.execute()

            for subnetwork in response['items']:
                # TODO: Change code below to process each `subnetwork` resource:
                logger.info(subnetwork)

            request = compute_service.subnetworks().list_next(previous_request=request, previous_response=response)

        logger.info("--------------------------------------------")
    return


def describe_networks():
    global network
    request = compute_service.networks().list(project=project)
    logger.info("\n\n--------------------------------------------")
    logger.info("Networks in project {}:".format(project))
    logger.info("--------------------------------------------")

    while request is not None:
        response = request.execute()

        for net in response['items']:
            logger.info(net['name'])

        logger.info("\n--------------------------------------------")
        logger.info("Subnetworks in Network {}:".format(network['name']))
        logger.info("--------------------------------------------")

        for net in response['items']:
            if net['name'] == network['name']:

                # Save the selflink for ue in other queries
                network['selfLink'] = net['selfLink']
                for subnw in net['subnetworks']:
                    logger.info(subnw)

        request = compute_service.subnetworks().list_next(previous_request=request, previous_response=response)

    return


def describe_instances():

    logger.info("\n--------------------------------------------")
    logger.info("Instances in VPC {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for zone in zones_list:
        request = compute_service.instances().list(project=project, zone=zone)

        while request is not None:
            response = request.execute()

            if 'items' in response:
                for instance in response['items']:
                    if network['name'] in instance['networkInterfaces'][0]['network']:
                        logger.info("{}, zone: {}".format(instance['name'],zone))

            request = compute_service.instances().list_next(previous_request=request, previous_response=response)

    return


def describe_fw_rules():
    logger.info("\n--------------------------------------------")
    logger.info("FW rules in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    request = compute_service.firewalls().list(project=project)
    while request is not None:
        response = request.execute()

        if 'items' in response:
            for firewall in response['items']:
                if firewall['network'] == network['selfLink']:
                    logger.info(firewall['name'])

        request = compute_service.firewalls().list_next(previous_request=request, previous_response=response)
    return


def describe_routes():
    logger.info("\n--------------------------------------------")
    logger.info("Routes in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    request = compute_service.routes().list(project=project)
    while request is not None:
        response = request.execute()

        if 'items' in response:
            for route in response['items']:
                if route['network'] == network['selfLink']:
                    logger.info("{} destination range: {}".format(route['name'], route['destRange']))

        request = compute_service.routes().list_next(previous_request=request, previous_response=response)

    return


def describe_vpn_gw():
    logger.info("\n--------------------------------------------")
    logger.info("VPN GW in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for region in regions_list:
        request = compute_service.vpnGateways().list(project=project, region=region)
        while request is not None:
            response = request.execute()
            if 'items' in response:
                for vpn_gw in response['items']:
                    if vpn_gw['network'] == network['selfLink']:
                        logger.info(vpn_gw['name'])

            request = compute_service.vpnGateways().list_next(previous_request=request, previous_response=response)

    return


def describe_forwarding_rules():
    logger.info("\n--------------------------------------------")
    logger.info("Forwarding rules in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for region in regions_list:
        request = compute_service.forwardingRules().list(project=project, region=region)
        while request is not None:
            response = request.execute()
            # if 'items' in response:
            #     for rule in response['items']:
                    # if vpn_gw['network'] == network['selfLink']:
            logger.info(response)

            request = compute_service.forwardingRules().list_next(previous_request=request, previous_response=response)

    return

def describe_routers():
    logger.info("\n--------------------------------------------")
    logger.info("Routers in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for region in regions_list:
        request = compute_service.routers().list(project=project, region=region)
        while request is not None:
            response = request.execute()

            if 'items' in response:
                for router in response['items']:
                    if router['network'] == network['selfLink']:
                        logger.info(router['name'])

            request = compute_service.routers().list_next(previous_request=request, previous_response=response)

    return


def describe_addresses():
    logger.info("\n--------------------------------------------")
    logger.info("Addresses in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for region in regions_list:
        request = compute_service.addresses().list(project=project, region=region)
        while request is not None:
            response = request.execute()
            # logger.info(response)

            if 'items' in response:
                for address in response['items']:
                    # if address['network'] == network['selfLink']:
                    logger.info("{} ,users: {}".format(address['name'], address['users']))

            request = compute_service.addresses().list_next(previous_request=request, previous_response=response)

    return


def describe_access_connectors():
    logger.info("\n--------------------------------------------")
    logger.info("Addresses in Network {}:".format(network['name']))
    logger.info("--------------------------------------------")

    for region in regions_list:
        # TODO: Find the access connectors method
        request = compute_service.vpcaccess().list(project=project, region=region)
        while request is not None:
            response = request.execute()
            # logger.info(response)

            if 'items' in response:
                for address in response['items']:
                    # if address['network'] == network['selfLink']:
                    logger.info("{} ,users: {}".format(address['name'], address['users']))

            request = compute_service.addresses().list_next(previous_request=request, previous_response=response)

    return


if __name__ == '__main__':
    helper_describe_regions()
    helper_describe_zones()
    describe_networks()
    describe_instances()
    describe_fw_rules()
    describe_routes()
    describe_vpn_gw()
    describe_routers()
    describe_addresses()
    # describe_access_connectors()
    # describe_forwarding_rules()
