# This script uses Azure AD application and service principal to authenticate and access resources.
# For details on how to create such an App check out:
# https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal
import logging

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.common.credentials import ServicePrincipalCredentials

subscription_id = 'XXXX'
tenant_id = 'XXXX'
client_id = 'XXXX'
client_secret = 'XXXX'

credentials = ServicePrincipalCredentials(tenant=tenant_id, client_id=client_id, secret=client_secret)

# Obtain the management object for resources.
resource_client = ResourceManagementClient(credentials, subscription_id)
compute_client = ComputeManagementClient(credentials, subscription_id)



# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')

#
# def print_item(group):
#     """Print a ResourceGroup instance."""
#     print("\tName: {}".format(group.name))
#     print("\tId: {}".format(group.type))
#     # print("\tLocation: {}".format(group.location))
#     # print("\tTags: {}".format(group.tags))
#     # print_properties(group.properties)
#
#
# def print_properties(props):
#     """Print a ResourceGroup properties instance."""
#     if props and props.provisioning_state:
#         print("\tProperties:")
#         print("\t\tProvisioning State: {}".format(props.provisioning_state))
#     print("\n")


def list_groups():
    # Retrieve the list of resource groups
    group_list = resource_client.resource_groups.list()
    logger.info("Resource groups in subscription {}:".format(subscription_id))
    logger.info("--------------------------------------------")
    logger.info("")
    for group in list(group_list):
        # print(f"{group.name:<{column_width}}{group.location}")
        logger.info("VMs in {}  ({}) ResourceGroup:".format(group.name, group.location))
        list_vms_in_a_group(group.name)

    return


def list_vms_in_a_group(group_name):

    # group_name = 'MC_alonresourcegroup_AKS_self_managed_eastus'
    # logger.info("")
    # logger.info("vms in group {}:".format(group_name))
    # logger.info("--------------------------------------------")
    for resource in resource_client.resources.list_by_resource_group(group_name):
        # logger.info(resource.type)
        # if resource.type == "Microsoft.Compute/virtualMachines":
        # print_resource(resource)
        logger.info("   Name: {}".format(resource.name))
        logger.info("   Type: {}".format(resource.type))

        if resource.type == "Microsoft.Compute/virtualMachineScaleSets":
            vmss = compute_client.virtual_machine_scale_set_vms.list(group_name, resource.name)
            for vm in vmss:
                logger.info("   Name: {}".format(vm.name))
                logger.info("   Type: {}".format(vm.type))
                logger.info("   Id: {}".format(vm.id))

                logger.info("   ScaleSet: {}".format(resource.name))
                vm_id = vm.id.split('/')[-1]
                # logger.info(vm_id)
                # a=   compute_client.virtual_machine_scale_sets.delete_instances(group_name, resource.name, [vm_id])
                # print (a)
    logger.info("")

    return


if __name__ == '__main__':
    list_groups()
    # list_vms_in_a_group()
