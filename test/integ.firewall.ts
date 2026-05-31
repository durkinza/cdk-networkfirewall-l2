//import { IntegTest } from 'aws-cdk-lib/integ-tests-alpha';
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as cdk from "aws-cdk-lib/core";
import * as NetFW from "../src/lib";

/**
 * An integration test using the Firewall L2
 *
 */
class TestStack extends cdk.Stack {
  /**
   *
   * @param scope - The CDK Stack SCope
   * @param id - The name for this stack.
   * @param properties - Optional additional stack properties
   */
  constructor(scope: cdk.App, id: string, properties?: cdk.StackProps) {
    super(scope, id, properties);
    const vpc = new ec2.Vpc(this, "MyTestVpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.0.0.0/16"),
    });

    // Setting up logging locations
    // const cloudWatchLogGroup = new logs.LogGroup(this, 'MyFirewallLogGroup');

    const s3LoggingBucket = new s3.Bucket(this, "MyFirewallLogBucket");

    // const kinesisStream = new kinesis.Stream(this, 'MyFirewallStream', {
    //   streamName: 'my-test-stream',
    // });

    // Setup Stateful 5Tuple rule & Group

    const stateful5TupleRule = new NetFW.Stateful5TupleRule({
      action: NetFW.StatefulStandardAction.DROP,
      destinationPort: "$WEB_PORTS",
      destination: "$HOME_NET",
      protocol: "TCP",
      sourcePort: "any",
      source: "10.10.0.0/16",
      direction: NetFW.Stateful5TupleDirection.FORWARD,
      ruleOptions: [
        {
          keyword: "sid",
          settings: ["1234"],
        },
      ],
    });

    const stateful5TupleRuleGroup = new NetFW.Stateful5TupleRuleGroup(
      this,
      "MyStateful5TupleRuleGroup",
      {
        capacity: 100,
        rules: [stateful5TupleRule],
        variables: {
          ipSets: {
            HOME_NET: { definition: ["10.0.0.0/16", "10.10.0.0/16"] },
          },
          portSets: {
            WEB_PORTS: { definition: ["443", "80"] },
          },
        },
        summaryConfiguration: {
          ruleOptions: ["MSG"],
        },
        // ruleOrder: NetFW.StatefulRuleOptionsRuleOrder.ACTION_ORDER,
      },
    );

    // Setup Stateful Domain list rule & Group

    const statefulDomainListRule = new NetFW.StatefulDomainListRule({
      type: NetFW.StatefulDomainListType.DENYLIST,
      targets: [".example.com", "www.example.org"],
      targetTypes: [
        NetFW.StatefulDomainListTargetType.TLS_SNI,
        NetFW.StatefulDomainListTargetType.HTTP_HOST,
      ],
    });

    const statefulDomainListRuleGroup = new NetFW.StatefulDomainListRuleGroup(
      this,
      "MyStatefulDomainListRuleGroup",
      {
        capacity: 100,
        rule: statefulDomainListRule,
        // ruleOrder: NetFW.StatefulRuleOptionsRuleOrder.ACTION_ORDER,
      },
    );

    // Setup Stateful Suricata rule & Group

    const statefulSuricataRuleGroup = new NetFW.StatefulSuricataRuleGroup(
      this,
      "MyStatefulSuricataRuleGroup",
      {
        capacity: 100,
        rules:
          'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\".htpasswd access attempt\"; flow:to_server,established; content:\".htpasswd\"; nocase; sid:210503; rev:1;)',
        variables: {
          ipSets: {
            HTTP_SERVERS: { definition: ["10.0.0.0/16"] },
          },
          portSets: {
            HTTP_PORTS: { definition: ["80", "8080"] },
          },
        },
        // ruleOrder: NetFW.StatefulRuleOptionsRuleOrder.ACTION_ORDER,
      },
    );

    // Setup Stateless rule & group

    const statelessRule = new NetFW.StatelessRule({
      actions: [NetFW.StatelessStandardAction.DROP],
      destinationPorts: [
        {
          fromPort: 80,
          toPort: 80,
        },
        {
          fromPort: 443,
          toPort: 443,
        },
      ],
      destinations: ["10.0.0.0/16"],
      protocols: [6],
      sourcePorts: [
        {
          fromPort: 0,
          toPort: 65535,
        },
      ],
      sources: ["10.0.0.0/16", "10.10.0.0/16"],
    });

    const statelessRuleGroup = new NetFW.StatelessRuleGroup(
      this,
      "MyStatelessRuleGroup",
      {
        ruleGroupName: "MyStatelessRuleGroup",
        rules: [{ rule: statelessRule, priority: 10 }],
      },
    );

    // Finally setup Policy and firewall.
    const policy = new NetFW.FirewallPolicy(this, "MyNetworkfirewallPolicy", {
      statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
      //ruleOrder: NetFW.StatefulEngineOptionsRuleOrder.ACTION_ORDER,
      statefulRuleGroups: [
        {
          priority: 10,
          ruleGroup: statefulDomainListRuleGroup,
        },
        {
          priority: 20,
          ruleGroup: stateful5TupleRuleGroup,
        },
        {
          priority: 30,
          ruleGroup: statefulSuricataRuleGroup,
        },
      ],
      statelessRuleGroups: [
        {
          priority: 10,
          ruleGroup: statelessRuleGroup,
        },
      ],
    });

    new NetFW.Firewall(this, "networkFirewall", {
      firewallName: "my-network-firewall",
      vpc: vpc,
      policy: policy,
      enabledAnalysisTypes: [
        NetFW.FirewallAnalysisTypes.TLS_SNI,
        NetFW.FirewallAnalysisTypes.HTTP_HOST,
      ],
      // loggingCloudWatchLogGroups: [{
      //   logGroup: cloudWatchLogGroup.logGroupName,
      //   logType: NetFW.LogType.FLOW,
      // }],
      loggingS3Buckets: [
        {
          bucketName: s3LoggingBucket.bucketName,
          logType: NetFW.LogType.ALERT,
          prefix: "alerts",
        },
        {
          bucketName: s3LoggingBucket.bucketName,
          logType: NetFW.LogType.FLOW,
          prefix: "flow",
        },
        {
          bucketName: s3LoggingBucket.bucketName,
          logType: NetFW.LogType.TLS,
          prefix: "tls",
        },
      ],
      // loggingKinesisDataStreams: [{
      //   deliveryStream: kinesisStream.streamName,
      //   logType: NetFW.LogType.ALERT,
      // }],
    });
  }
}

const app = new cdk.App();
cdk.Tags.of(app).add("Project", "NetworkFirewallL2IntegTest");
new TestStack(app, "network-firewall-integ-stack");

app.synth();
