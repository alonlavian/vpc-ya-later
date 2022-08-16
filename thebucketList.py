###############################################################
#        List and offer to delete all your S3 buckets         #
###############################################################

import logging
import boto3
from argparse import ArgumentParser, HelpFormatter
from botocore.exceptions import ClientError, ProfileNotFound

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')

# Argument parser config
formatter = lambda prog: HelpFormatter(prog, max_help_position=52)
parser = ArgumentParser(formatter_class=formatter)
parser = ArgumentParser()
parser.add_argument("-p", '--profile', default='default', help="AWS profile")
args = parser.parse_args()

# boto client config
try:
    session = boto3.Session(profile_name=args.profile)
except ProfileNotFound as e:
    logger.warning("{}, please provide a valid AWS profile name".format(e))
    exit(-1)

s3_client = session.client('s3')
s3 = boto3.resource('s3')


def list_buckets():
    buckets = s3_client.list_buckets()

    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        logger.info("Found the bucket: {}".format(bucket_name))
        try:
            s3_objects = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=5)['Contents']
            keys = [key['Key'] for key in s3_objects]
            for count, key in enumerate(keys):
                logger.info("         Sample data {}: {}".format(count, key))
        except:
            logger.info("         The bucket is empty")

        delete_bucket(bucket_name)


def delete_bucket(bucket_name):
    logger.info("Do you want to delete {}? (y/n)".format(bucket_name))
    yes = input().lower() == 'y'
    if yes:
        bucket_versioning = s3.BucketVersioning(bucket_name)
        s3_bucket = s3.Bucket(bucket_name)
        # boto3.set_stream_logger('',  level= 4)
        boto3.set_stream_logger(name='botocore')
        if bucket_versioning.status == 'Enabled':
            s3_bucket.object_versions.delete()
        else:
            s3_bucket.objects.all().delete()
        response = s3_bucket.delete()
        logger.info("{}".format(response))


if __name__ == '__main__':
    list_buckets()
