# VPC Ya Later

A collection of scripts to help you deal with loose ends on multi cloud environments.

* VPC Ya Later - Annihilate an AWS VPC and all its resources.
* GCP inside - List all resources in a GCP network
* Lama Vnet - List all resource groups in a subscirption and their content (WIP)
* The bucket list -  List, empty and delete all your S3 buckets 

## Requirements:

* Python version: 3.8.12
* AWS
  * Boto3 version: 1.20.26
  * Botocore version: 1.23.26
  * Valid AWS API keys/profile
* GCP
  * googleapiclient
  * google.oauth2
  * A credentials file
* Azure
  * azure.mgmt
  * azure.common
  * Client ID and secret

## Usage

```
vpc-ya-later.py [-h] -v VPC [-r REGION] [-d] [-p PROFILE]

optional arguments:
  -h, --help                    show this help message and exit
  -v VPC, --vpc VPC             The VPC to annihilate
  -r REGION, --region REGION    AWS region that the VPC resides in
  -d, --dryrun                  If exists, dry run all deletions.
  -p PROFILE, --profile PROFILE AWS profile
```
## License
[MIT](https://choosealicense.com/licenses/mit/)

## Important, please read !!!

The script will try to delete every resource within the VPC. Please use with caution.

Resources that can be deleted:

* EC2
* EKS
* ASG
* Lambda
* RDS
* ELB
* ELBv2
* NAT
* VPC Endpoint
* VPC IGW
* VPC VPGW
* ENI
* Routing tables
* Security groups
* ACLs
* VPC

