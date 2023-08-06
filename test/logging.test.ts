import { Template } from 'aws-cdk-lib/assertions';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as S3 from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib/core';
import * as NetFW from '../src/lib';

describe('Testing Logging Features', ()=>{
  let stack: cdk.Stack;
  let vpc: ec2.Vpc;
  beforeEach(() => {
    // GIVEN
    stack = new cdk.Stack();
    vpc = new ec2.Vpc(stack, 'MyTestVpc', {
      ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
    });
  });

  test('Cloudwatch Logs', () => {
    // GIVEN
    const logGroup = new logs.LogGroup(stack, 'MyCustomLogGroup');

    // WHEN
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy1', {
      statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });
    new NetFW.Firewall(stack, 'MyNetworkFirewall30', {
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

  test('Cloudwatch with bad name throws Error', () => {
    // WHEN
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy1', {
      statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });

    // THEN
    expect(() => {
      new NetFW.Firewall(stack, 'MyNetworkFirewall', {
        vpc: vpc,
        policy: policy,
        loggingCloudWatchLogGroups: [
          {
            logGroup: 'Test_!test',
            logType: NetFW.LogType.ALERT,
          },
        ],
      });
    // THEN
    }).toThrow('Cloudwatch LogGroup must have 1-512 characters of only letters, numbers, hyphens, underscores, and pounds (#). Got: Test_!test');

  });

  test('S3 Logs', () => {
    // GIVEN
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

  test('S3 Bucket with Bad prefix throws Error', () => {
    // GIVEN
    const logBucket = new S3.Bucket(stack, 'MyCustomLogBucket');

    // WHEN
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy2', {
      statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });

    // THEN
    expect(() => {
      new NetFW.Firewall(stack, 'MyNetworkFirewall11', {
        vpc: vpc,
        policy: policy,
        loggingS3Buckets: [
          {
            prefix: '#test&ing',
            bucketName: logBucket.bucketName,
            logType: NetFW.LogType.ALERT,
          },
        ],
      });
    // THEN
    }).toThrow('Bucket Name prefix must have only letters, numbers, hyphens, dots (.), underscores, parantheses, stars(*), and explaination points (!). Got: #test&ing');
  });


  test('Kinesis Data Streams Logs', () => {
    // GIVEN
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


  test('Kinesis Data Streams with Bad Name throws Error', () => {
    // WHEN
    const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy3', {
      statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
    });

    // THEN
    expect(() => {
      new NetFW.Firewall(stack, 'MyNetworkFirewall12', {
        vpc: vpc,
        policy: policy,
        loggingKinesisDataStreams: [
          {
            deliveryStream: 'test_!test',
            logType: NetFW.LogType.FLOW,
          },
        ],
      });
    // THEN
    }).toThrow('Kinesis deliveryStream must have 1-64 characters of only letters, numbers, hyphens, dots (.), and underscores. Got: test_!test');
  });
});