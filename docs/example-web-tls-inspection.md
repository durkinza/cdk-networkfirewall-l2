```ts
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib/core';
import NetFW from '@durkinza/cdk-networkfirewall-l2';


/**
 * Props for configuring the WebFirewallTlsInspectionStack
 */
export interface WebFirewallTlsInspectionStackProps extends cdk.StackProps {

  /**
   * The VPC where the ALB and firewall reside.
   */
  readonly vpc: ec2.IVpc,

  /**
   * The S3 bucket to store firewall logs.
   */
  readonly loggingS3Bucket: s3.IBucket,

  /**
   * The domain name for the website (e.g. example.com).
   */
  readonly domainName: string,
}

/**
 * A Network Firewall stack that protects a website with TLS inspection.
 *
 * The firewall is deployed to the public subnets where the ALB resides and
 * performs TLS inspection on inbound HTTPS traffic using an ACM certificate.
 */
export class WebFirewallTlsInspectionStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: WebFirewallTlsInspectionStackProps) {
    super(scope, id, props);

    // Generate an ACM certificate for the domain.
    // DNS validation requires a hosted zone; for this example, use email validation
    // or replace with a Route53-based validation if you have a hosted zone.
    const certificate = new acm.Certificate(this, 'SiteCertificate', {
      domainName: props.domainName,
      subjectAlternativeNames: [`*.${props.domainName}`],
      validation: acm.CertificateValidation.fromEmail(),
    });

    // TLS Inspection Configuration using the ACM certificate.
    // This allows the firewall to decrypt inbound HTTPS traffic for inspection.
    const tlsInspection = new NetFW.TLSInspectionConfiguration(this, 'TlsInspection', {
      configurationName: 'web-tls-inspection',
      description: 'TLS inspection for inbound web traffic',
      serverCertificateConfigurations: [{
        serverCertificates: [{
          resourceArn: certificate.certificateArn,
        }],
        scopes: [{
          // Inspect inbound HTTPS (port 443) destined for the VPC
          destinationPorts: [{ fromPort: 443, toPort: 443 }],
          destinations: [{ addressDefinition: props.vpc.vpcCidrBlock }],
          protocols: [6], // TCP
          sourcePorts: [{ fromPort: 0, toPort: 65535 }],
          sources: [{ addressDefinition: '0.0.0.0/0' }],
        }],
        checkCertificateRevocationStatus: {
          revokedStatusAction: 'DROP',
          unknownStatusAction: 'PASS',
        },
      }],
    });

    // Domain list rule group: allow traffic only to our domain
    const domainAllowList = new NetFW.StatefulDomainListRuleGroup(this, 'DomainAllowList', {
      ruleGroupName: 'web-domain-allow-list',
      capacity: 100,
      rule: new NetFW.StatefulDomainListRule({
        type: NetFW.StatefulDomainListType.ALLOWLIST,
        targets: [`.${props.domainName}`],
        targetTypes: [
          NetFW.StatefulDomainListTargetType.TLS_SNI,
          NetFW.StatefulDomainListTargetType.HTTP_HOST,
        ],
      }),
    });

    // Firewall policy with TLS inspection and strict ordering
    const policy = new NetFW.FirewallPolicy(this, 'WebFirewallPolicy', {
      firewallPolicyName: 'web-firewall-policy',
      // Forward all traffic to stateful rules for deep inspection
      statelessDefaultActions: [NetFW.StatelessStandardAction.FORWARD],
      statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.FORWARD],
      // Drop established connections that don't match any stateful rule
      statefulDefaultActions: [NetFW.StatefulStrictAction.DROP_ESTABLISHED],
      statefulRuleGroups: [{
        priority: 10,
        ruleGroup: domainAllowList,
      }],
      // Attach TLS inspection
      tlsInspectionConfiguration: tlsInspection,
    });

    // Deploy the firewall to the public subnets (where the ALB lives)
    new NetFW.Firewall(this, 'WebFirewall', {
      firewallName: 'web-tls-firewall',
      vpc: props.vpc,
      policy: policy,
      subnetMappings: { subnetType: ec2.SubnetType.PUBLIC },
      loggingS3Buckets: [
        {
          bucketName: props.loggingS3Bucket.bucketName,
          logType: NetFW.LogType.ALERT,
          prefix: 'alerts',
        },
        {
          bucketName: props.loggingS3Bucket.bucketName,
          logType: NetFW.LogType.FLOW,
          prefix: 'flow',
        },
        {
          bucketName: props.loggingS3Bucket.bucketName,
          logType: NetFW.LogType.TLS,
          prefix: 'tls',
        },
      ],
    });
  }
}

// Deploy the stack
const app = new cdk.App();
new WebFirewallTlsInspectionStack(app, 'web-firewall-tls-inspection-stack', {
  // Replace with your VPC and S3 bucket names
  vpc: ec2.Vpc.fromLookup(app, 'myVPC', { vpcName: '<MyVPCName>' }),
  loggingS3Bucket: s3.Bucket.fromBucketName(app, 'myBucket', '<MyBucketName>'),
  domainName: 'example.com',
});

app.synth();
```
