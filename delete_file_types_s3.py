###############################################################
#        List and offer to delete all your S3 buckets         #
###############################################################

import boto3
s3 = boto3.resource('s3')

for bucket in s3.meta.client.list_buckets()['Buckets']:
    for count, obj in enumerate(s3.Bucket(bucket['Name']).objects.filter()):
        if obj.key.endswith('.json.gz') or obj.key.endswith('.txt'):
            print("{}: deleting: {} from: {}".format(count, obj.key, bucket['Name']))
            s3.meta.client.delete_object(Bucket=bucket['Name'], Key=obj.key)
