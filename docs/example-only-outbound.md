```ts
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib/core';
import NetFW from '@durkinza/cdk-networkfirewall-l2';
import { Bucket } from 'aws-cdk-lib/aws-s3';


/**
 * Props for configuring the NonObtrusiveNetworkFirewallStack
 */
export interface NonObtrusiveNetworkFirewallStackProps extends cdk.StackProps{

  /**
   * The VPC for the firewall to listen on.
   */
  readonly vpc: ec2.IVpc,

  /**
   * The S3 bucket to store traffic logs.
   */
  readonly loggingS3Bucket: s3.IBucket

}

/**
 * A Non-obtrusive, monitoring example for the AWS Network Firewall
 *
 */
export class NonObtrusiveNetworkFirewallStack extends cdk.Stack {
  /**
   *
   * @param scope - The CDK Stack SCope
   * @param id - The name for this stack.
   * @param props - Additional stack properties
   */
  constructor(scope: cdk.App, id: string, props: NonObtrusiveNetworkFirewallStackProps) {
    super(scope, id, props);

    // Setup Rule Group to allow all outbound and no inbound
    const ruleGroup = new NetFW.Stateful5TupleRuleGroup(this, 'PassiveStatefulRuleGroup', {
      ruleGroupName: 'PassiveStatefulRuleGroup',
      rules: [
        
        // Allow outbound ipv4 traffic
        new NetFW.Stateful5TupleRule({
          action: NetFW.StatefulStandardAction.PASS,
          source: props.vpc.vpcCidrBlock,
          destination: '0.0.0.0/0',
        }),
        // Allow outbound ipv6 traffic
        new NetFW.Stateful5TupleRule({
          action: NetFW.StatefulStandardAction.PASS,
          source: props.vpc.vpcCidrBlock,
          destination: '::/0',
        })
      ],
    });

    // Finally setup Policy and firewall.
    const policy = new NetFW.FirewallPolicy(this, 'MyNetworkfirewallPolicy', {
      // Send all traffic to Stateful rules for inspection
      statelessDefaultActions: [NetFW.StatelessStandardAction.FORWARD],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.FORWARD],
      // Drop all other traffic that doesn't match the stateful rules
      statefulDefaultActions: [NetFW.StatefulStandardAction.DROP],
      statefulRuleGroups: [
        {
          ruleGroup: ruleGroup,
        },
      ],
    });
    
    new NetFW.Firewall(this, 'networkFirewall', {
      firewallName: 'my-network-firewall',
      vpc: props.vpc,
      policy: policy,
      loggingS3Buckets: [
        {
          bucketName: props.loggingS3Bucket.bucketName,
          logType: NetFW.LogType.ALERT,
          prefix: 'alerts',
        },
      ],
    });
  }
}

// Now call the stack in your app
const app = new cdk.App();
new NonObtrusiveNetworkFirewallStack(app, 'network-firewall-passive-monitoring-stack', {
  // Replace <MyVPCName> and <MyBucketName> with your VPC and S3 bucket names
  vpc: ec2.Vpc.fromLookup(app,'myVPC',{vpcName:"<MyVPCName>"}),
  loggingS3Bucket: Bucket.fromBucketName(app, 'myBucket', "<MyBucketName>")
});

app.synth();
```