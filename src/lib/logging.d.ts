import { Construct } from 'constructs';
import { CfnLoggingConfiguration } from 'aws-cdk-lib/aws-networkfirewall';
import * as core from 'aws-cdk-lib/core';
/**
 * The type of log to send.
 */
export declare enum LogType {
    /**
     * Alert logs report traffic that matches a stateful rule with an action setting that sends an alert log message.
     */
    ALERT = "ALERT",
    /**
     * Flow logs are standard network traffic flow logs.
     */
    FLOW = "FLOW"
}
/**
 * The type of storage destination to send these logs to.
 */
export declare enum LogDestinationType {
    /**
    * Store logs to CloudWatch log group.
    */
    CLOUDWATCH = "CloudWatchLogs",
    /**
     * Store logs to a Kinesis Data Firehose delivery stream.
     */
    KINESISDATAFIREHOSE = "KinesisDataFirehose",
    /**
     * Store logs to an S3 bucket.
     */
    S3 = "S3"
}
/**
 * Defines a Log Location in the Stack.
 */
export interface ILogLocation {
    /**
     * The type of log to send.
     */
    readonly logType: LogType | string;
    /**
     * The type of storage destination to send these logs to.
     */
    readonly logDestinationType: LogDestinationType | string;
    /**
     * The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.
     */
    readonly logDestination: {
        [key: string]: string;
    };
}
/**
 * Base Log Location structure.
 */
export interface LogLocationProps {
    /**
     * The type of log to send.
     */
    readonly logType: LogType | string;
}
/**
 * Base Log Location class
 */
export declare abstract class LogLocationBase implements ILogLocation {
    readonly logType: LogType | string;
    readonly logDestinationType: LogDestinationType | string;
    abstract readonly logDestination: {
        [key: string]: string;
    };
    constructor(logDestinationType: LogDestinationType, props: LogLocationProps);
}
/**
 * Defines a S3 Bucket Logging Option.
 */
export interface S3LogLocationProps extends LogLocationProps {
    /**
     * The name of the S3 bucket to send logs to.
     */
    readonly bucketName: string;
    /**
     * The location prefix to use
     *
     * @default - no prefix is used.
     */
    readonly prefix?: string;
}
/**
 * Defines a S3 Bucket Logging configuration.
 */
export declare class S3LogLocation extends LogLocationBase {
    readonly logType: LogType | string;
    readonly logDestinationType: LogDestinationType | string;
    readonly logDestination: {
        [key: string]: string;
    };
    constructor(props: S3LogLocationProps);
}
/**
 * Defines a Kinesis Delivery Stream Logging Option.
 */
export interface KinesisDataFirehoseLogLocationProps extends LogLocationProps {
    /**
     * The name of the Kinesis Data Firehose delivery stream to send logs to.
     */
    readonly deliveryStream: string;
}
/**
 * Defines a Kinesis Delivery Stream Logging Configuration.
 */
export declare class KinesisDataFirehoseLogLocation extends LogLocationBase {
    readonly logType: LogType | string;
    readonly logDestinationType: LogDestinationType | string;
    readonly logDestination: {
        [key: string]: string;
    };
    constructor(props: KinesisDataFirehoseLogLocationProps);
}
/**
 * Defines a Cloud Watch Log Group Logging Option.
 */
export interface CloudWatchLogLocationProps extends LogLocationProps {
    /**
     * The name of the CloudWatch Log Group to send logs to.
     */
    readonly logGroup: string;
}
/**
 * Defines a Cloud Watch Log Group Logging Configuration.
 */
export declare class CloudWatchLogLocation extends LogLocationBase {
    readonly logType: LogType | string;
    readonly logDestinationType: LogDestinationType | string;
    readonly logDestination: {
        [key: string]: string;
    };
    constructor(props: CloudWatchLogLocationProps);
}
/**
  * Defines a Network Firewall Logging Configuration in the stack
  */
export interface ILoggingConfiguration extends core.IResource {
    /**
     * The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with.
     * You can't change the firewall specification after you create the logging configuration.
     *
     * @attribute
     */
    readonly firewallRef: string;
}
/**
 * The Properties for defining a Logging Configuration
 */
export interface LoggingConfigurationProps {
    /**
     * The physical name of this logging configuration
     *
     * @default - CloudFormation-generated name
     */
    readonly loggingConfigurationName?: string;
    /**
     * The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with.
     * You can't change the firewall specification after you create the logging configuration.
     */
    readonly firewallRef: string;
    /**
     * The name of the firewall that the logging configuration is associated with.
     * You can't change the firewall specification after you create the logging configuration.
     *
     * @default - No firewall name is logged.
     */
    readonly firewallName?: string;
    /**
     * Defines how AWS Network Firewall performs logging for a Firewall.
     *
     * @default - No logging locations are configured, no logs will be sent.
     */
    readonly loggingLocations?: ILogLocation[];
}
/**
 * Defines a Logging Configuration in the Stack
 * @resource AWS::NetworkFirewall::LoggingConfiguration
 */
export declare class LoggingConfiguration extends core.Resource implements ILoggingConfiguration {
    /**
     * The associated firewall Arn
     * @attribute
     */
    readonly firewallRef: string;
    /**
     * The associated firewall Name
     * @attribute
     */
    readonly firewallName?: string;
    /**
     * Defines how AWS Network Firewall performs logging for a Firewall.
     *
     */
    loggingLocations: ILogLocation[];
    constructor(scope: Construct, id: string, props: LoggingConfigurationProps);
    /**
     * Convert ILogLocation array to L1 LogDestinationConfigProperty array.
     * @param logLocations An array of assorted Log Locations
     * @returns Array of LogDestinationConfigProperty objects.
     */
    iLogLocationsToLogDestinationConfigProperty(logLocations: ILogLocation[]): CfnLoggingConfiguration.LogDestinationConfigProperty[];
}
