import { Construct } from 'constructs';
import { ILogLocation, S3LogLocationProps, KinesisDataFirehoseLogLocationProps, CloudWatchLogLocationProps, LoggingConfiguration, ILoggingConfiguration } from './logging';
import { IFirewallPolicy } from './policy';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as core from 'aws-cdk-lib/core';
/**
 * Defines a Network Firewall in the stack
 */
export interface IFirewall extends core.IResource {
    /**
     * The Arn of the Firewall.
     *
     * @attribute
     */
    readonly firewallArn: string;
    /**
     * The physical name of the Firewall.
     *
     * @attribute
     */
    readonly firewallId: string;
}
/**
 * Defines a Network Firewall
 */
declare abstract class FirewallBase extends core.Resource implements IFirewall {
    abstract readonly firewallArn: string;
    abstract readonly firewallId: string;
}
/**
 * The Properties for defining a Firewall Resource
 */
export interface FirewallProps {
    /**
     * The descriptive name of the firewall.
     * You can't change the name of a firewall after you create it.
     *
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
     *
     * @default - All public subnets of the VPC
     */
    readonly subnetMappings?: ec2.SubnetSelection;
    /**
     * The descriptiong of the Firewall
     *
     * @default - undefined
     */
    readonly description?: string;
    /**
     * A flag indicating whether it is possible to delete the firewall.
     * A setting of TRUE indicates that the firewall is protected against deletion
     *
     * @default - true
     */
    readonly deleteProtection?: boolean;
    /**
     * A setting indicating whether the firewall is protected against a change to the firewall policy association.
     * Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use.
     *
     * @default - true
     */
    readonly firewallPolicyChangeProtection?: boolean;
    /**
     * A setting indicating whether the firewall is protected against changes to the subnet associations.
     * Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use.
     *
     * @default - true
     */
    readonly subnetChangeProtection?: boolean;
    /**
     * Tags to be added to the firewall.
     *
     * @default - No tags applied
     */
    readonly tags?: core.Tag[];
    /**
     * A list of CloudWatch LogGroups to send logs to.
     *
     * @default - Logs will not be sent to a cloudwatch group.
     */
    readonly loggingCloudWatchLogGroups?: CloudWatchLogLocationProps[];
    /**
     * A list of S3 Buckets to send logs to.
     *
     * @default - Logs will not be sent to an S3 bucket.
     */
    readonly loggingS3Buckets?: S3LogLocationProps[];
    /**
     * A list of S3 Buckets to send logs to.
     *
     * @default - Logs will not be sent to an S3 bucket.
     */
    readonly loggingKinesisDataStreams?: KinesisDataFirehoseLogLocationProps[];
}
/**
 * Defines a Network Firewall in the Stack
 * @resource AWS::NetworkFirewall::Firewall
 */
export declare class Firewall extends FirewallBase {
    /**
     * Reference an existing Network Firewall,
     * defined outside of the CDK code, by name.
     */
    static fromFirewallName(scope: Construct, id: string, firewallName: string): IFirewall;
    /**
     * Reference an existing Network Firewall,
     * defined outside of the CDK code, by arn.
     */
    static fromFirewallArn(scope: Construct, id: string, firewallArn: string): IFirewall;
    /**
     * The Arn of the Firewall.
     *
     * @attribute
     */
    readonly firewallArn: string;
    /**
     * The physical name of the Firewall.
     *
     * @attribute
     */
    readonly firewallId: string;
    /**
     * The unique IDs of the firewall endpoints for all of the subnets that you attached to the firewall.
     * The subnets are not listed in any particular order.
     *
     * @attribute
     */
    readonly endpointIds: string[];
    /**
     * The associated firewall Policy
     * @attribute
     */
    readonly policy: IFirewallPolicy;
    /**
     * The Cloud Watch Log Groups to send logs to.
     * @attribute
     */
    loggingCloudWatchLogGroups: CloudWatchLogLocationProps[];
    /**
     * The S3 Buckets to send logs to.
     * @attribute
     */
    loggingS3Buckets: S3LogLocationProps[];
    /**
     * The Kinesis Data Stream locations.
     * @attribute
     */
    loggingKinesisDataStreams: KinesisDataFirehoseLogLocationProps[];
    /**
    * The list of references to the generated logging configurations.
    */
    loggingConfigurations: ILoggingConfiguration[];
    constructor(scope: Construct, id: string, props: FirewallProps);
    /**
     * Add a Logging Configuration to the Firewall.
     * @param configurationName The Name of the Logging configuration type.
     * @param logLocations An array of Log Locations.
     * @returns A LoggingConfiguration Resource.
     */
    addLoggingConfigurations(configurationName: string, logLocations: ILogLocation[]): LoggingConfiguration;
    /**
     * Cast SubnetSelection to a list ofsubnetMappingProperty
     */
    private castSubnetMapping;
}
export {};
