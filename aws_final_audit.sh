#!/bin/bash

read -p "Enter the profile name: " profile
read -p "Enter the output file name: " output

required_details() {
	echo "[+] Listing all Users"
	aws iam list-users --query "Users[*].UserName" --profile  $profile  | awk -F '"' '{print $2}' | sed '/^$/d' | tee audit_users.txt

	echo "[+] Listing all Active regions"
	aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 | tee active_regions.txt

	echo "[+] Listing all s3 buckets"
	aws s3 ls --profile  $profile  | awk -F " " '{print $3}' > s3_buckets
}
#- - - - - - - -  Initial function call - - - - - - - -
required_details

accounts() {
echo "[Check] - Maintain current contact details" | tee -a $output
echo "[Command] - aws account get-contact-information" | tee -a $output
echo "[+] Compliant if contact details exists" | tee -a $output

aws account get-contact-information --profile $profile  | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure security contact information is registered" | tee -a $output
echo "[Command] - aws account get-alternate-contact --alternate-contact-type SECURITY" | tee -a $output
echo "[+] Compliant if alternate contact exists" | tee -a $output

aws account get-alternate-contact --alternate-contact-type SECURITY --profile $profile | tee -a $output

echo "-----------------------------------"  | tee -a $output
echo ""  | tee -a $output


echo "[Check] - Ensure hardware MFA is enabled for the 'root' user account." | tee -a $output
echo "[Command] - aws iam list-mfa-devices --profile  $profile" | tee -a $output
echo '[+] Compliant if not empty & serial number not equal to "SerialNumber": "arn:aws:iam::_<aws_account_number>_:mfa/root-account-mfa-device' | tee -a $output

aws iam list-mfa-devices --profile  $profile | tee -a $output
aws iam list-virtual-mfa-devices --profile  $profile | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output
}

iam() {
echo "[Check] - Ensure no 'root' user account access key exists" | tee -a $output
echo "[Command] - aws iam get-account-summary"
echo "[+] Compliant if AccountAccessKeysPresent is 0" | tee -a $output
account_summary=$(aws iam get-account-summary --profile  $profile)
echo $account_summary | jq . | tee -a $output
echo $account_summary | jq . | grep "AccountAccessKeysPresent" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure MFA is enabled for the 'root' user account" | tee -a $output
echo "[Command] - aws iam get-account-summary"
echo "[+] Compliant if AccountMFAEnabled is 1" | tee -a $output

echo $account_summary | jq . | grep "AccountMFAEnabled" | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure IAM password policy requires minimum length of 14 or greater" | tee -a $output
echo '[Command] - aws iam get-account-password-policy --profile  $profile | grep "MinimumPasswordLength"' | tee -a $output
echo "[+] Compliant if MinimumPasswordLength is >=14" | tee -a $output

passwd_policy=$(aws iam get-account-password-policy --profile  $profile)
echo $passwd_policy | jq . | tee -a $output
echo $passwd_policy | jq . | grep "MinimumPasswordLength" | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure IAM password policy prevents password reuse" | tee -a $output
echo '[Command] - aws iam get-account-password-policy --profile  $profile | grep "PasswordReusePrevention"' | tee -a $output
echo "[+] Compliant if PasswordReusePrevention is =24" | tee -a $output

echo $passwd_policy | jq . | grep "PasswordReusePrevention" | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password" | tee -a $output
echo "[Command] - aws iam get-credential-report --query 'Content' --output text --profile  $profile | base64 -d |cut -d, -f1,4,8"  | tee -a $output
echo "[+] Compliant if mfa_active is true for true password_enabled" | tee -a $output

creds_report=$(aws iam get-credential-report --query 'Content' --output text --profile $profile)
echo $creds_report | tee -a $output
echo $creds_report | base64 -d |cut -d, -f1,4,8 | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure credentials unused for 45 days or greater are disabled" | tee -a $output
echo "[Command] - aws iam get-credential-report --query 'Content' --output text --profile  $profile | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16 | grep -v '^<root_account>"  | tee -a $output
echo "[+] Compliant if For each user having password_enabled set to TRUE , ensure password_last_used_date is less than 45 days ago." | tee -a $output

echo $creds_report | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16 | grep -v '^<root_account>' | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure access keys are rotated every 90 days or less" | tee -a $output
echo "[Command] - aws iam get-credential-report --query 'Content' --output text --profile  $profile"  | tee -a $output
echo "[+] Compliant if access key age is less than 90 days" | tee -a $output

echo $creds_report | base64 -d | cut -d, -f1,4,5,6 | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure there is only one active access key available for any single IAM user" | tee -a $output
echo "[Command] - aws iam list-access-keys --user-name $user --profile  $profile" | tee -a $output
echo "[+] Compliant if For each user having only one active Access ID." | tee -a $output
#aws iam list-users --query "Users[*].UserName" --profile  $profile  | awk -F '"' '{print $2}' | sed '/^$/d' | tee audit_users.txt

while IFS= read -r user;do
        echo "[*] Check for user: $user" | tee -a $output
        aws iam list-access-keys --user-name $user --profile  $profile  | tee -a $output
        echo "" | tee -a $output
done < audit_users.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure IAM Users Receive Permissions Only Through Groups" | tee -a $output
echo "[Command] - aws iam list-attached-user-policies --user-name $user --profile  $profile" | tee -a $output
echo "[Command] - aws iam list-user-policies --user-name $user --profile  $profile" | tee -a $output
echo "[+] Compliant if For each user having only one active Access ID" | tee -a $output

while IFS= read -r user;do
        echo "[*] Check for user: $user" | tee -a $output
        aws iam list-attached-user-policies --user-name $user --profile  $profile  | tee -a $output
        aws iam list-user-policies --user-name $user --profile  $profile  | tee -a $output
        echo "" | tee -a $output
done < audit_users.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure IAM policies that allow full ''*:*'' administrativeprivileges are not attached" | tee -a $output
echo "[Command] - aws iam list-policies --only-attached --output json --profile  $profile" | tee -a $output
echo '[Command] - aws iam get-policy-version --policy-arn "$arn" --version-id "$defaultVersionID" --profile  $profile' | tee -a $output
echo "[+] Compliant if no vulnerable found" | tee -a $output

echo "[*] Listing policies - " | tee -a $output
aws iam list-policies --only-attached --output json --profile  $profile  | tee -a $output | jq > policies.json

cat ./policies.json | jq -c '.Policies[]' | while IFS= read -r policy; do
    arn=$(echo "$policy" | jq -r '.Arn')
    defaultVersionID=$(echo "$policy" | jq -r '.DefaultVersionId')

    echo "Checking policy ARN: $arn with version ID: $defaultVersionID" | tee -a $output


    if aws iam get-policy-version --policy-arn "$arn" --version-id "$defaultVersionID" --profile  $profile  | tee -a $output  | grep -E '"Resource": "\*"|"Action": "\*"|"Effect": "Allow"';
    then
        echo "Vulnerable" | tee -a $output
    fi
done
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] -  Ensure a support role has been created to manage incidents with AWS Support" | tee -a $output
echo "[Command] - aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --profile  $profile" | tee -a $output
echo "[+] Compliant if PolicyRoles does not return empty" | tee -a $output

if aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --profile  $profile | tee -a $output | grep -E '\"PolicyRoles\": \[\]'
then
        echo "Non-Compliant" | tee -a $output
fi

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure access to AWSCloudShellFullAccess is restricted" | tee -a $output
echo "[Command] - aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess --profile  $profile" | tee -a $output
echo "[+] Compliant if PolicyRoles does not return empty." | tee -a $output

if aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess --profile  $profile | tee -a $output | grep -E '\"PolicyRoles\": \[\]'
then
        echo "Compliant" | tee -a $output
fi

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

}

access_analyzer() {

echo "[Check] -  Ensure that IAM Access analyzer is enabled for all regions" | tee -a $output
echo "[Command] - aws accessanalyzer list-analyzers --region $region --profile  $profile" | tee -a $output
echo "[+] Compliant if All status is set to Active" | tee -a $output

#aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 > active_regions.txt

while IFS= read -r region; do
if aws accessanalyzer list-analyzers --region $region --profile  $profile | tee -a $output | grep -iE '\"analyzers\": \[\]|\"status\": \[Active\]';
then
        echo "[-]Checking for $region : Non-compliant" | tee -a $output
fi
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

}

s3buckets() {

echo "[Check] -  Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'" | tee -a $output
echo "[Command] - aws s3api get-public-access-block --bucket $s3bucket --profile  $profile" | tee -a $output
echo "[+] Compliant if BlockPublicAcls does return true." | tee -a $output
#aws s3 ls --profile  $profile  | awk -F " " '{print $3}' > s3_buckets

while IFS= read -r s3bucket;do
echo "[+] Checking for S3: $s3bucket" | tee -a $output
if aws s3api get-public-access-block --bucket $s3bucket --profile  $profile | tee -a $output | grep -iE '\"BlockPublicAcls\": true'
then
        echo "[+] Compliant" | tee -a $output
fi
done <  s3_buckets
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure S3 Bucket Policy is set to deny HTTP requests" | tee -a $output
echo "[Command] - aws s3api get-bucket-policy --bucket $bucketname --profile  $profile  2>/dev/null --output text " | tee -a $output
echo "[+] Compliant if aws:SecureTransport is set to false aws:SecureTransport:false" | tee -a $output

aws s3 ls --profile  $profile  --output text | awk -F " " '{print $3}' | tee s3bucketsList | tee -a $output
while IFS= read -r bucketname;
do
  echo "[+] Checking for s3 $bucketname" | tee -a $output
  aws s3api get-bucket-policy --bucket $bucketname --profile  $profile --output text 2>/dev/null | jq . | tee -a $output
done < s3bucketsList
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure that Object-level logging for write events is enabled for S3 bucket " | tee -a $output
echo "[Command] - aws cloudtrail get-event-selectors --trail-name  $name --profile  $profile  --region $region --query EventSelectors[*].DataResources[]" | tee -a $output
echo "[+] Compliant if flow is not empty" | tee -a $output

while IFS= read -r region; do
  while IFA= read -r name;do
       echo "[+] Checking for region $region and trail $name"  | tee -a $output
       aws cloudtrail get-event-selectors --trail-name  $name --profile  $profile  --region $region --query EventSelectors[*].DataResources[] | tee -a $output
  done < cloudtrailNames
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure that Object-level logging for read events is enabled for S3 bucket"  | tee -a $output
echo "[Command] - aws cloudtrail get-event-selectors --trail-name  $name --profile  $profile  --region $region" | tee -a $output
echo "[+] Compliant if flow is not empty" | tee -a $output

while IFS= read -r region; do
  while IFA= read -r name;do
	echo "[+] Checking for region $region & trail $name" | tee -a $output
        aws cloudtrail get-event-selectors --trail-name  $name --profile  $profile  --region $region 2>/dev/null  | tee -a $output
  done < cloudtrailNames
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

}

ebs() {

echo "[Check] -  Ensure EBS Volume Encryption is Enabled in all Regions" | tee -a $output
echo "[Command] - aws ec2 get-ebs-encryption-by-default --region $region --profile  $profile " | tee -a $output
echo "[+] Compliant if All regions EbsEncryptionByDefault is set to true" | tee -a $output
#aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 > active_regions.txt

while IFS= read -r region; do
echo "[*] Checking for region: $region" | tee -a $output
        if aws ec2 get-ebs-encryption-by-default --region $region --profile  $profile | tee -a $output | grep -E '\"EbsEncryptionByDefault\": true'
        then
                echo "[+] $region - Compliant" | tee -a $output
        else
                echo "[-] $region - Non-Compliant" | tee -a $output
        fi
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


}

rds() {

echo "[Check] -  Ensure that encryption-at-rest is enabled for RDS Instances" | tee -a $output
echo "[Command] - aws rds describe-db-instances --region $region --query 'DBInstances[*].DBInstanceIdentifier' --profile  $profile" | tee -a $output
echo "[+] Compliant if All regions StorageEncrypted  is set to true" | tee -a $output

#aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 > active_regions.txt

while IFS= read -r region; do
if aws rds describe-db-instances --region $region --query 'DBInstances[*].DBInstanceIdentifier' --profile  $profile  2>/dev/null | tee -a $output | grep -vE '\[\]';
then
     aws rds describe-db-instances --region $region --query 'DBInstances[*].DBInstanceIdentifier' --profile  $profile  | tee -a $output | awk -F '"' '{print $2}' | sed '/^$/d' > rds_$region
     while IFS= read -r rds;do
             echo "[+] Checking RDS : $rds in Region $region" | tee -a $output
             aws rds describe-db-instances --region $region --db-instance-identifier $rds --query 'DBInstances[*].StorageEncrypted' --profile  $profile | tee -a $output
     done < rds_$region
fi

done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] -  Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances" | tee -a $output
echo "[Command] - aws rds describe-db-instances --region $region --db-instance-identifier $rds --query 'DBInstances[*].AutoMinorVersionUpgrade' --profile  $profile " | tee -a $output
echo "[+] Compliant if All regions status is set to true" | tee -a $output
while IFS= read -r region; do
if aws rds describe-db-instances --region $region --query 'DBInstances[*].DBInstanceIdentifier' --profile  $profile 2>/dev/null | tee -a $output | grep -vE '\[\]';
then
        while IFS= read -r rds;do
        echo "[+] Checking RDS : $rds in Region $region" | tee -a $output
        if aws rds describe-db-instances --region $region --db-instance-identifier $rds --query 'DBInstances[*].AutoMinorVersionUpgrade' --profile  $profile | tee -a $output | grep -i true;
        then
                echo "$rds in $region is Compliant" | tee -a $output
        else
                echo "$rds in $region is Non-compliant" | tee -a $output
        fi
        done < rds_$region
fi
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] -  Ensure that public access is not given to RDS Instance" | tee -a $output
echo "[Command] - aws rds describe-db-instances --region $region --db-instance-identifier $rds --query 'DBInstances[*].PubliclyAccessible' --profile  $profile" | tee -a $output
echo "[+] Compliant if All regions status is set to true" | tee -a $output

while IFS= read -r region; do
if aws rds describe-db-instances --region $region --query 'DBInstances[*].DBInstanceIdentifier' --profile  $profile  2>/dev/null | tee -a output | grep -vE '\[\]';
then
  while IFS= read -r rds;do
    aws rds describe-db-instances --region $region --db-instance-identifier $rds --query 'DBInstances[*].PubliclyAccessible' --profile  $profile | tee -a $output
  done < rds_$region
fi

done < active_regions.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output



}


efs() {

echo "[Check] -  Ensure that encryption is enabled for EFS file systems" | tee -a $output
echo "[Command] - aws efs describe-file-systems --region $region --file-system-id $fs --query 'FileSystems[*].Encrypted' --profile  $profile" | tee -a $output
echo "[+] Compliant if All regions status is set to true" | tee -a $output
#aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 > active_regions.txt
while IFS= read -r region; do
echo "Checking for region: $region" | tee -a $output
aws efs describe-file-systems --region $region --output table --query 'FileSystems[*].FileSystemId' --profile  $profile  --output text 2>/dev/null | tee -a $output|  tee  fs_$region

  while IFS= read -r fs; do
    if aws efs describe-file-systems --region $region --file-system-id $fs --query 'FileSystems[*].Encrypted' --profile  $profile | tee -a $output | grep -i true
    then
        echo "[+] Region $region - Compliant" | tee -a $output
    else
        echo "[-] Region $region - Non-Compliant" | tee -a $output
    fi
  done < fs_$region
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

}

cloudtrail() {

echo "[Check] -  Ensure CloudTrail is enabled in all regions" | tee -a $output
echo "[Command] - aws cloudtrail describe-trails --profile  $profile  --region $region --trail-name $name" | tee -a $output
echo "[+] Compliant if loging All regions  is set to true" | tee -a $output

while IFS= read -r region; do
echo "Checking for region: $region"
  aws cloudtrail describe-trails --profile  $profile  --region $region 2>/dev/null | tee -a $output | tee cloudtrails
done < active_regions.txt

echo "Listing cloudtrailNames"
cat ./cloudtrails | grep -w Name | awk -F '"' '{print $4}' | sort -u | tee -a $output | tee cloudtrailNames

#cat ./cloudtrails | jq -c '.trailList[]' | jq -r '.S3BucketName' | sort -u > s3cloudtrailNames
while IFS= read -r region; do
  while IFA= read -r name;do

        if aws cloudtrail describe-trails --profile  $profile  --region $region --trail-name $name | tee -a $output | grep -E '\"IsMultiRegionTrail"\: true';
        then
                echo "Cloudtrail $name is compliant for MultiRegion in $region region" | tee -a $output
        else
                echo "Cloudtrail $name is not Compliant in $region region" | tee -a $output
        fi
        if aws cloudtrail get-trail-status --name $name --profile  $profile  --region $region | tee -a $output | grep -E '\"IsLogging\": true';
        then
                echo "Cloudtrail $name is compliant for Logging in $region region" | tee -a $output
        else
                echo "Cloudtrail $name is not Compliant in $region region" | tee -a $output
        fi
        if aws cloudtrail get-event-selectors --trail-name  $name --profile  $profile  --region $region  | tee -a $output | grep -E '\"ReadWriteType\": \"All\"|\"IncludeManagementEvents\": true';
        then
                echo "Cloudtrail $name is compliant for ManagementEvents in $region region" | tee -a $output
        else
                echo "Cloudtrail $name is not Compliant in $region region" | tee -a $output
        fi
  done < cloudtrailNames
done < active_regions.txt
echo "-----------------------------------"
echo "" | tee -a $output


echo "[Check] -  Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible" | tee -a $output
echo "[Command] - aws s3api get-public-access-block --bucket $bucketname --profile  $profile" | tee -a $output
echo "[+] Compliant if all settings are set to true" | tee -a $output
echo "listing s3 buckets names used for cloudtrails - "
cat ./cloudtrails | grep -w S3BucketName | awk -F '"' '{print $4}' | sort -u  | tee -a $output | tee s3cloudtrailNames
while IFS= read -r bucketname;do
        if aws s3api get-public-access-block --bucket $bucketname --profile  $profile | tee -a $output | grep -E '\"BlockPublicAcls\"\: true|\"IgnorePublicAcls\"\: true|\"BlockPublicPolicy\"\: true|\"RestrictPubicBuckets"\: true';
        then
                echo "[+] S3 bucket $bucketname is Compliant" | tee -a $output
        else
                echo "[-] S3 bucket $bucketname is Non-Compliant" | tee -a $output
        fi
done < s3cloudtrailNames
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure CloudTrail trails are integrated with CloudWatch Logs" | tee -a $output
echo "[Command] - aws cloudtrail describe-trails --profile  $profile  --region $region | tee -a $output | grep -E '\"CloudWatchLogsRoleArn\"|\"CloudWatchLogsLogGroupArn\"' -A 4 -B 10 "| tee -a $output
echo "[+] Compliant if CloudWatchLogsRoleArn & CloudWatchLogsLogGroupArn are present" | tee -a $output

cat ./cloudtrails  | tee -a $output | grep -E '"CloudWatchLogsRoleArn"|"CloudWatchLogsLogGroupArn"' -A 4 -B 10 | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket" | tee -a $output
echo "[Command] - aws s3api get-bucket-logging --bucket $bucketname --profile  $profile"
echo "[+] Compliant if returned not-empty" | tee -a $output
while IFS= read -r bucketname;do
  if aws s3api get-bucket-logging --bucket $bucketname --profile  $profile | tee -a $output | grep -i logging;
  then
        echo "[+] Bucket $bucketname is Compliant for bucket Access logging" | tee -a $output
  else
        echo "[-] Bucket $bucketname is Non-Compliant " | tee -a $output
  fi
done < s3cloudtrailNames
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure CloudTrail logs are encrypted at rest using KMS CMKs" | tee -a $output
echo "[Command] - aws cloudtrail describe-trails --profile  $profile  --region $region" | tee -a $output
echo "[+] Compliant if KmsKeyId property defined." | tee -a $output
cat ./cloudtrails | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


}


monitoring() {
echo "[Check] - Ensure S3 bucket policy changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo ""

echo "[Check] -  Ensure management console sign-in without MFA is Monitored " | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo ""

echo "[Check] -  Ensure IAM policy changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] -  Ensure usage of 'root' account is monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure CloudTrail configuration changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure changes to network gateways are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure route table changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure VPC changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure AWS Organizations changes are monitored" | tee -a $output
echo "[Command] - aws logs describe-metric-filters --log-group-name $cloudwatcgLogGroupName --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Check MANUALLY" | tee -a $output
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output
}

networkACL() {

echo "[Check] - Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" | tee -a $output
echo "[Command] - aws ec2 describe-network-acls --profile  $profile  --region us-east-1 --query 'NetworkAcls[0].Entries' " | tee -a $output
echo "[+] Compliant if no ingress rule is set to allow traffic from any ip to administrative port" | tee -a $output

aws ec2 describe-network-acls --profile  $profile  --region us-east-1 --query 'NetworkAcls[0].Entries' | tee -a $output

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports" | tee -a $output
echo "[Command] - aws ec2 describe-security-groups --group-ids $group_id --query 'SecurityGroups[*].{ID:GroupId,IpPermissions:IpPermissions}' --output text --profile  $profile  --region us-east-1" | tee -a $output
echo "[+] Compliant if no ingress rule is set to allow traffic from any ip to administrative port" | tee -a $output

aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}' --profile  $profile  --region us-east-1 --output text | awk -F ' ' '{print $1}' | tee securityGroups | tee -a $output

while IFS= read -r group_id;do
  aws ec2 describe-security-groups --group-ids $group_id --query 'SecurityGroups[*].{ID:GroupId,IpPermissions:IpPermissions}' --output text --profile  $profile  --region us-east-1 | tee -a $output
done < securityGroups
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure that EC2 Metadata Service only allows IMDSv2" | tee -a $output
echo '[Command] - aws ec2 describe-instances --region $region --instance-ids $instanceid --query "Reservations[*].Instances[*].MetadataOptions" --output table --profile  $profile' | tee -a $output
echo "[+] Compliant if HttpTokens is set to required and State is set to applied." | tee -a $output
#aws ec2 describe-regions --all-regions --query "Regions[].{Name:RegionName}" --output text --profile  $profile  --region us-east-1 > active_regions.txt

while IFS= read -r region;do
  echo "[+] Checking for Region $region"
  aws ec2 describe-instances --region $region --profile  $profile  --output text --query "Reservations[*].Instances[*].InstanceId" 2>/dev/null | tee instance_ids_$region | tee -a $output
  while IFA= read -r instanceid;do
    echo "[+] Checking for Instance $instanceid in $region region"
    aws ec2 describe-instances --region $region --instance-ids $instanceid --query "Reservations[*].Instances[*].MetadataOptions" --output table --profile  $profile | tee instance_$instanceid | tee -a $output
  done < instance_ids_$region
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output



}

vpc() {

echo "[Check] - Ensure VPC flow logging is enabled in all VPCs" | tee -a $output
echo '[Command] - aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --region $region --profile  $profile' | tee -a $output
echo "[+] Compliant if flow is not empty." | tee -a $output

while IFS= read -r region;do
  echo "[+] Checking for region $region" | tee -a $output
  aws ec2 describe-vpcs --region $region --query Vpcs[].VpcId --profile  $profile  --output text 2>/dev/null | tee vpc_$region | tee -a $output
  while IFS= read -r vpc;do
        aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --region $region --profile  $profile  2>/dev/null | tee -a $output
  done < vpc_$region
done < active_regions.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

echo "[Check] - Ensure the default security group of every VPC restricts all traffic." | tee -a $output
echo '[Command] - aws ec2 describe-security-groups --query "SecurityGroups[*].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}" --filter "Name=group-name,Values=default" --profile $profile --region $region' | tee -a $output
echo "[+] Compliant if IpPermissions & IpPermissionsEgree is []" | tee -a $output

while IFS= read -r region
do
  echo "[+] Checking for region $region" | tee -a $output
  aws ec2 describe-security-groups --query "SecurityGroups[*].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}" --filter "Name=group-name,Values=default" --profile $profile --region $region | tee -a $output
done < active_regions.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output

}


aws() {

echo "[Check] - Ensure AWS Security Hub is enabled" | tee -a $output
echo "[Command] - aws securityhub describe-hub --profile  $profile  --region $region"  | tee -a $output
echo "[+] Compliant if flow is not empty or no error" | tee -a $output
while IFS= read -r region
do
  echo "[+] Checking for $region" | tee -a $output
  aws securityhub describe-hub --profile  $profile  --region $region | tee -a $output
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


echo "[Check] - Ensure rotation for customer created KMS CMKs is enabled." | tee -a $output
echo "[Command] - aws kms get-key-rotation-status --key-id $key --profile  $profile  --region $region  " | tee -a $output
echo "[+] Compliant if "KeyRotationEnabled": true" | tee -a $output

while IFS= read -r region;
do
aws kms list-keys --profile  $profile  --region $region 2>/dev/null | grep -i keyid | awk -F '"' '{print $4}' | tee keyId  | tee -a $output
  while IFS= read -r key;
  do
    echo "[+] Checking for key $key" | tee -a $output
    aws kms get-key-rotation-status --key-id $key --profile  $profile  --region $region | tee -a $output
  done < keyId
done < active_regions.txt

echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output




echo "[Check] - Ensure a log metric filter and alarm exist for unauthorized API calls." | tee -a $output
echo "[Command] - aws cloudwatch describe-alarms-for-metric --metric-name UnauthorizedAPICalls --namespace AWS/Logs --profile  $profile  --region $region  " | tee -a $output
echo "[+] Compliant if not empty" | tee -a $output

while IFA= read -r region;
do
  aws cloudwatch describe-alarms-for-metric --metric-name UnauthorizedAPICalls --namespace AWS/Logs --profile  $profile  --region $region  | tee -a $output
done < active_regions.txt
echo "-----------------------------------" | tee -a $output
echo "" | tee -a $output


}

##  - - - - - - - - All function Calls - - - - - - - - - ##
accounts
iam
access_analyzer
s3buckets
ebs
rds
efs
cloudtrail
monitoring
networkACL
vpc
aws
