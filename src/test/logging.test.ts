//import { Template, Match } from 'aws-cdk-lib//assertions';
import { Template } from 'aws-cdk-lib/assertions';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as S3 from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib/core';
import * as NetFW from '../lib';

test('Cloudwatch Logs', () => {
  // GIVEN
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'MyTestVpc', {
    ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
  });

  const logGroup = new logs.LogGroup(stack, 'MyCustomLogGroup');

  // WHEN
  const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy1', {
    statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
    statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
  });
  new NetFW.Firewall(stack, 'MyNetworkFirewall10', {
    vpc: vpc,
    policy: policy,
    loggingCloudWatchLogGroups: [
      {
        logGroup: logGroup.logGroupName,
        logType: NetFW.LogType.ALERT,
      },
    ],
  });

  // THEN
  Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::Firewall', {
    SubnetMappings: [
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet1SubnetA7B59A2C',
        },
      },
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet2SubnetBE93625D',
        },
      },
    ],
    VpcId: {
      Ref: 'MyTestVpcE144EEF4',
    },
  });
});

test('S3 Logs', () => {
  // GIVEN
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'MyTestVpc', {
    ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
  });

  const logBucket = new S3.Bucket(stack, 'MyCustomLogBucket');

  // WHEN
  const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy2', {
    statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
    statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
  });
  new NetFW.Firewall(stack, 'MyNetworkFirewall11', {
    vpc: vpc,
    policy: policy,
    loggingS3Buckets: [
      {
        bucketName: logBucket.bucketName,
        logType: NetFW.LogType.ALERT,
      },
    ],
  });

  // THEN
  Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::Firewall', {
    SubnetMappings: [
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet1SubnetA7B59A2C',
        },
      },
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet2SubnetBE93625D',
        },
      },
    ],
    VpcId: {
      Ref: 'MyTestVpcE144EEF4',
    },
  });
});

test('Kinesis Data Streams Logs', () => {
  // GIVEN
  const stack = new cdk.Stack();
  const vpc = new ec2.Vpc(stack, 'MyTestVpc', {
    ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
  });

  const stream = new kinesis.Stream(stack, 'MyTestStream', {
    streamName: 'my-test-stream',
  });

  // WHEN
  const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy3', {
    statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
    statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
  });

  new NetFW.Firewall(stack, 'MyNetworkFirewall12', {
    vpc: vpc,
    policy: policy,
    loggingKinesisDataStreams: [
      {
        deliveryStream: stream.streamName,
        logType: NetFW.LogType.FLOW,
      },
    ],
  });

  // THEN
  Template.fromStack(stack).hasResourceProperties('AWS::NetworkFirewall::Firewall', {
    SubnetMappings: [
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet1SubnetA7B59A2C',
        },
      },
      {
        SubnetId: {
          Ref: 'MyTestVpcPublicSubnet2SubnetBE93625D',
        },
      },
    ],
    VpcId: {
      Ref: 'MyTestVpcE144EEF4',
    },
  });
});