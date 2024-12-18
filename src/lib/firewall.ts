import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { CfnFirewall, CfnFirewallProps } from 'aws-cdk-lib/aws-networkfirewall';
import * as core from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import { EncryptionConfiguration } from './encryption-configuration';
import {
  ILogLocation,
  S3LogLocationProps,
  S3LogLocation,
  KinesisDataFirehoseLogLocationProps,
  KinesisDataFirehoseLogLocation,
  CloudWatchLogLocationProps,
  CloudWatchLogLocation,
  LoggingConfiguration,
  ILoggingConfiguration,
} from './logging';
import { IFirewallPolicy } from './policy';

/**
 * Defines a Network Firewall in the stack
 */
export interface IFirewall extends core.IResource{
  /**
   * The Arn of the Firewall.
   * @attribute
   */
  readonly firewallArn: string;

  /**
   * The physical name of the Firewall.
   * @attribute
   */
  readonly firewallId: string;

  /**
   * The unique IDs of the firewall endpoints for all of the subnets that you attached to the firewall.
   * The subnets are not listed in any particular order.
   * @attribute
   */
  //readonly endpointIds: string[];
}

/**
 * Defines a Network Firewall
 */
abstract class FirewallBase extends core.Resource implements IFirewall {
  public abstract readonly firewallArn: string;
  public abstract readonly firewallId: string;
  //public abstract readonly endpointIds: string[];
}

/**
 * The Properties for defining a Firewall Resource
 */
export interface FirewallProps {
  /**
   * The descriptive name of the firewall.
   * You can't change the name of a firewall after you create it.
   * @default - CloudFormation-generated name
   */
  readonly firewallName?: string;

  /**
   * The unique identifier of the VPC where the firewall is in use. You can't change the VPC of a firewall after you create the firewall.
   *
   */
  readonly vpc: ec2.IVpc;

  /**
   * Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.
   *
   */
  readonly policy: IFirewallPolicy;

  /**
   * The public subnets that Network Firewall is using for the firewall. Each subnet must belong to a different Availability Zone.
   * @default - All public subnets of the VPC
   */
  readonly subnetMappings?: ec2.SubnetSelection;

  /**
   * The description of the Firewall
   * @default - undefined
   */
  readonly description?: string;

  /**
   * A flag indicating whether it is possible to delete the firewall.
   * A setting of TRUE indicates that the firewall is protected against deletion
   * @default - true
   */
  readonly deleteProtection?: boolean;

  /**
   * Not yet supported in Cloudformation at time of writing.
   * You can use a customer managed key in AWS Key Management Service (KMS) to encrypt your data at rest.
   * If you don’t configure a customer managed key, Network Firewall encrypts your data using an AWS managed key.
   * @default - AWS managed key is used
   */
  readonly encryptionConfiguration?: EncryptionConfiguration;

  /**
   * A setting indicating whether the firewall is protected against a change to the firewall policy association.
   * Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use.
   * @default - true
   */
  readonly firewallPolicyChangeProtection?: boolean;

  /**
   * A setting indicating whether the firewall is protected against changes to the subnet associations.
   * Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use.
   * @default - true
   */
  readonly subnetChangeProtection?: boolean;

  /**
   * Tags to be added to the firewall.
   * @default - No tags applied
   */
  readonly tags?: core.Tag[];

  /**
   * A list of CloudWatch LogGroups to send logs to.
   * @default - Logs will not be sent to a cloudwatch group.
   */
  readonly loggingCloudWatchLogGroups?: CloudWatchLogLocationProps[];

  /**
   * A list of S3 Buckets to send logs to.
   * @default - Logs will not be sent to an S3 bucket.
   */
  readonly loggingS3Buckets?: S3LogLocationProps[];

  /**
   * A list of Kinesis Data Firehose to send logs to.
   * @default - Logs will not be sent to a Kinesis DataFirehose.
   */
  readonly loggingKinesisDataStreams?: KinesisDataFirehoseLogLocationProps[];
}

/**
 * Defines a Network Firewall in the Stack
 * @resource AWS::NetworkFirewall::Firewall
 */
export class Firewall extends FirewallBase {

  /**
   * Reference an existing Network Firewall,
   * defined outside of the CDK code, by name.
   * @param scope
   * @param id
   * @param firewallName
   */
  public static fromFirewallName(scope: Construct, id: string, firewallName: string): IFirewall {
    if (core.Token.isUnresolved(firewallName)) {
      throw new Error('All arguments to Firewall.fromFirewallName must be concrete (no Tokens)');
    }

    /**
     * An ADHOC class for the imported firewall.
     */
    class Import extends FirewallBase {
      public readonly firewallId = firewallName;
      // Since we have the name, we can generate the ARN,
      public readonly firewallArn = core.Stack.of(scope)
        .formatArn({
          service: 'network-firewall',
          resource: 'firewall',
          resourceName: firewallName,
        });
      //public readonly endpointIds = [''];
    }
    return new Import(scope, id);
  }

  /**
   * Reference an existing Network Firewall,
   * defined outside of the CDK code, by arn.
   * @param scope
   * @param id
   * @param firewallArn
   */
  public static fromFirewallArn(scope: Construct, id: string, firewallArn: string): IFirewall {
    if (core.Token.isUnresolved(firewallArn)) {
      throw new Error('All arguments to Firewall.fromFirewallArn must be concrete (no Tokens)');
    }
    /**
     * An ADHOC class for the imported Firewall.
     */
    class Import extends FirewallBase {
      public readonly firewallId = core.Fn.select(1, core.Fn.split('/', firewallArn));
      public readonly firewallArn = firewallArn;
      //public readonly endpointIds = [''];
    }
    return new Import(scope, id);
  }

  /**
   * The Arn of the Firewall.
   * @attribute
   */
  public readonly firewallArn: string;

  /**
   * The physical name of the Firewall.
   * @attribute
   */
  public readonly firewallId: string;

  /**
   * The unique IDs of the firewall endpoints for all of the subnets that you attached to the firewall.
   * The subnets are not listed in any particular order.
   * @attribute
   */
  public readonly endpointIds: string[];

  /**
   * The associated firewall Policy
   * @attribute
   */
  public readonly policy: IFirewallPolicy;

  /**
   * The Cloud Watch Log Groups to send logs to.
   * @attribute
   */
  public loggingCloudWatchLogGroups: CloudWatchLogLocationProps[];

  /**
   * The S3 Buckets to send logs to.
   * @attribute
   */
  public loggingS3Buckets: S3LogLocationProps[];

  /**
   * The Kinesis Data Stream locations.
   * @attribute
   */
  public loggingKinesisDataStreams: KinesisDataFirehoseLogLocationProps[];

  /**
   * The list of references to the generated logging configurations.
   */
  public loggingConfigurations: ILoggingConfiguration[];

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope:Construct, id: string, props: FirewallProps) {
    super(scope, id, {
      physicalName: props.firewallName,
    });

    // Adding Validations

    /*
     * Validate firewallName
     */
    if (props.firewallName !== undefined &&
				!/^[\dA-Za-z-]{1,128}$/.test(props.firewallName)) {
      throw new Error('firewallName must be non-empty and contain only letters, numbers, and dashes, ' +
				`got: '${props.firewallName}'`);
    }

    // Auto define new policy?
    //const firewallPolicy:IfirewallPolicy = props.policy ||
    //		new policy(scope, id, {
    //				statelessDefaultActions: [StatelessStandardAction.FORWARD]
    //				statelessFragmentDefaultActions: [StatelessStandardAction.FORWARD]
    //			}
    //		);

    // Auto pick subnetMappings from VPC if not provided
    let subnets:CfnFirewall.SubnetMappingProperty[]=[];
    if (props.subnetMappings === undefined) {
      let subnetMapping:ec2.SubnetSelection = props.vpc.selectSubnets({
        subnetType: ec2.SubnetType.PUBLIC,
      });
      subnets = this.castSubnetMapping(subnetMapping);
    } else {
      subnets = this.castSubnetMapping(props.subnetMappings);
    }

    const resourceProps:CfnFirewallProps = {
      deleteProtection: props.deleteProtection,
      description: props.description,
      // encryptionConfiguration: props.encryptionConfiguration, // Not supported by cloudformation yet.
      firewallName: props.firewallName||id,
      firewallPolicyArn: props.policy.firewallPolicyArn,
      firewallPolicyChangeProtection: props.firewallPolicyChangeProtection,
      subnetChangeProtection: props.subnetChangeProtection,
      subnetMappings: subnets,
      tags: props.tags || [],
      vpcId: props.vpc.vpcId,
    };

    const resource:CfnFirewall = new CfnFirewall(this, id, resourceProps);

    this.firewallId = this.getResourceNameAttribute(resource.ref);
    this.firewallArn = this.getResourceArnAttribute(resource.attrFirewallArn, {
      service: 'network-firewall',
      resource: 'firewall',
      resourceName: this.firewallId,
    });

    this.endpointIds = resource.attrEndpointIds;
    this.policy = props.policy;

    this.loggingConfigurations = [];
    this.loggingCloudWatchLogGroups = props.loggingCloudWatchLogGroups || [];
    this.loggingS3Buckets = props.loggingS3Buckets || [];
    this.loggingKinesisDataStreams = props.loggingKinesisDataStreams || [];

    // let logLocations: ILogLocation[] = [];

    if (props.loggingCloudWatchLogGroups) {
      let cloudWatchLogGroups: ILogLocation[] = [];
      let cloudWatchLogGroup:CloudWatchLogLocationProps;
      for (cloudWatchLogGroup of props.loggingCloudWatchLogGroups) {
        const logLocation:ILogLocation = new CloudWatchLogLocation(cloudWatchLogGroup);
        cloudWatchLogGroups.push(logLocation);
        // logLocations.push(logLocation);
      }
      this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-CloudWatch`, cloudWatchLogGroups));
    }

    if (props.loggingS3Buckets) {
      let s3LogGroups: ILogLocation[] = [];
      let s3LogGroup:S3LogLocationProps;
      for (s3LogGroup of props.loggingS3Buckets) {
        const logLocation:ILogLocation = new S3LogLocation(s3LogGroup);
        s3LogGroups.push(logLocation);
        // logLocations.push(logLocation);
      }
      this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-S3Buckets`, s3LogGroups));
    }

    if (props.loggingKinesisDataStreams) {
      let kinesisLogGroups: ILogLocation[] = [];
      let kinesisLogGroup: KinesisDataFirehoseLogLocationProps;
      for (kinesisLogGroup of props.loggingKinesisDataStreams) {
        const logLocation:ILogLocation = new KinesisDataFirehoseLogLocation(kinesisLogGroup);
        kinesisLogGroups.push(logLocation);
        // logLocations.push(logLocation);
      }
      this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-KinesisDataFirehose`, kinesisLogGroups));
    }
    // if (logLocations.length > 0) {
    //   this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-firewall-logging`, logLocations));
    // }
  }

  /**
   * Add a Logging Configuration to the Firewall.
   * @param configurationName The Name of the Logging configuration type.
   * @param logLocations An array of Log Locations.
   * @returns A LoggingConfiguration Resource.
   */
  public addLoggingConfigurations(configurationName: string, logLocations: ILogLocation[]) {
    return new LoggingConfiguration(this, configurationName, {
      firewallRef: this.firewallArn,
      firewallName: this.physicalName,
      loggingConfigurationName: configurationName,
      loggingLocations: logLocations,
    });
  }

  /**
   * Cast SubnetSelection to a list of subnetMappingProperty
   * @param subnetSelection
   */
  private castSubnetMapping(subnetSelection:ec2.SubnetSelection|undefined):CfnFirewall.SubnetMappingProperty[] {
    let subnets:CfnFirewall.SubnetMappingProperty[]=[];
    let subnet:ec2.ISubnet;
    if (subnetSelection !== undefined && subnetSelection.subnets !== undefined) {
      for (subnet of subnetSelection.subnets) {
        subnets.push({
          subnetId: subnet.subnetId,
        });
      }
    }
    return subnets;
  }
}
