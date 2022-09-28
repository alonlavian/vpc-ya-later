# VPC Inside  

**Description:** This tool can be used to describe all of your AWS VPC resources.  

**Note:**  
This is a fork/reqork of the original [vpc-inside.py](https://github.com/alonlavian/vpc-ya-later/blob/main/vpc-inside.py) by Alon Lavian.  

**I made the following updates:**  

- Added vpc-inside-requiements.txt
- Added README-vpc-inside.md (this file)
- Reworked original .py file added comments.
- Added colorization option of output.
- Added AWS Auth scripts.

```text
usage: vpc-inside.py [-h] -v VPC [-r REGION] [-p PROFILE]

optional arguments:
  -h, --help                     show this help message and exit
  -v VPC, --vpc VPC              The VPC to describe
  -r REGION, --region REGION     AWS region that the VPC resides in
  -p PROFILE, --profile PROFILE  AWS profile
  -c yes/no, --colorize yes/no   Add Colorization to output
```

**Note:**  

VPCs mostly contain EC2 instances, RDS instances, Load Balancers and Lambda functions. Plus, things that use EC2 underneath, like Elasticache. These are the types of resources that connect into a VPC.  

---

**Note:**  
This project uses the Amazon Boto3 Module.  

**If using automated AWS Auth script - call this first**  
*For Dev/Test*  
source scripts/awsauth.sh <TOKEN_CODE>  

**Example:**  
source scripts/awsauth.sh 123456

*For production use*  
source scripts/awsswitchrolemfa.sh <ROLE_ARN> <AWS_SESSION_NAME> <TOKEN_CODE>  

**Example:**  
source scripts/awsswitchrolemfa.sh arn:aws:iam::<AWS_ACCOUNT>:role/<YOUR_CROSS-ACCOUT-ROLE> aws-session 123456

**Note:** <TOKEN_CODE> comes from:  
1Password --> Account --> one time password  
Or whatever MFA program/device you use.  

---

**Pyhon Version Used:**  
Python 3.8.9 / 3.8.10

## Python Virtual Environment Setup (Linux)  

**Create the Virtual Environment (Example):**  
python3 -m venv ~/projects/vpc-ya-later/v-env  

**Activate the Virtual Environment (Example):**  
source ~/projects/vpc-ya-later/v-env/bin/activate  

**Generate Requirements for project:**  
To create vpc-inside-requirements.txt:  

1) Setup virtual environment  
2) Install all python packages  
   Example:  
~/projects/vpc-ya-later/v-env/bin/pip3 install <PACKAGE_NAME>
3) Note: Make sure to upgrade pip  
~/projects/vpc-ya-later/v-env/bin/pip3 install --upgrade pip  
4) run:  
[Path to Virtual Environment Bin Directory]/pip3 freeze > vpc-inside-requirements.txt  
Example (Linux):  
~/projects/vpc-ya-later/v-env/bin/pip3 freeze > vpc-inside-requirements.txt  

**Install the Requirements/Dependancies (Example):**  
~/projects/vpc-ya-later/v-env/bin/pip3 install -r vpc-inside-requirements.txt  

---

**Example usage:**  

Template:
`./vpc-inside.py -v <VPC> -r <REGION> -p <PROFILE> -c <yes/no>`

Example Call:
`./vpc-inside.py -v vpc-05308930963f9eca9 -r us-west-2 -p <default> -c yes`

---
