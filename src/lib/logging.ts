import { CfnLoggingConfiguration, CfnLoggingConfigurationProps } from 'aws-cdk-lib/aws-networkfirewall';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import * as core from 'aws-cdk-lib/core';
import { Construct } from 'constructs';

/**
 * The type of log to send.
 */
export enum LogType{
  /**
   * Alert logs report traffic that matches a stateful rule with an action setting that sends an alert log message.
   */
  ALERT = 'ALERT',

  /**
   * Flow logs are standard network traffic flow logs.
   */
  FLOW = 'FLOW',
};

/**
 * The type of storage destination to send these logs to.
 */
export enum LogDestinationType {
  /**
  * Store logs to CloudWatch log group.
  */
  CLOUDWATCH = 'CloudWatchLogs',

  /**
   * Store logs to a Kinesis Data Firehose delivery stream.
   */
  KINESISDATAFIREHOSE = 'KinesisDataFirehose',

  /**
   * Store logs to an S3 bucket.
   */
  S3 = 'S3',
};

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
  readonly logDestination: { [key:string]: string };
};

/**
 * Base Log Location structure.
 */
export interface LogLocationProps {
  /**
   * The type of log to send.
   */
  readonly logType: LogType | string;
};

/**
 * Base Log Location class
 */
export abstract class LogLocationBase implements ILogLocation {
  public readonly logType : LogType | string;
  public readonly logDestinationType: LogDestinationType | string;
  public abstract readonly logDestination: { [key: string]: string };
  constructor(logDestinationType:LogDestinationType, props:LogLocationProps) {
    this.logType=props.logType;
    this.logDestinationType = logDestinationType;
  }
};

/**
 * Defines a S3 Bucket Logging Option.
 */
export interface S3LogLocationProps extends LogLocationProps{
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
};

/**
 * Defines a S3 Bucket Logging configuration.
 */
export class S3LogLocation extends LogLocationBase {
  public readonly logType : LogType | string;
  public readonly logDestinationType : LogDestinationType | string;
  public readonly logDestination: { [key: string]: string };

  constructor(props:S3LogLocationProps) {
    super(LogDestinationType.S3, props);
    this.logDestinationType = LogDestinationType.S3;
    this.logType = props.logType;

    // Throws and error if bucketName is invalid format.
    Bucket.validateBucketName(props.bucketName);
    if (props.prefix) {
      if (!/^[a-zA-Z0-9_.!*'()-]{1,}$/.test(props.prefix)) {
        throw new Error(`'prefix' must have only letters, numbers, hyphens, dots (.), underscores, parantheses, stars(*), and explaination points (!). Got: ${props.prefix}`);
      }
      this.logDestination = {
        bucketName: props.bucketName,
        prefix: props.prefix,
      };
    } else {
      this.logDestination = {
        bucketName: props.bucketName,
      };
    }
  }
};

/**
 * Defines a Kinesis Delivery Stream Logging Option.
 */
export interface KinesisDataFirehoseLogLocationProps extends LogLocationProps{
  /**
   * The name of the Kinesis Data Firehose delivery stream to send logs to.
   */
  readonly deliveryStream: string;
};

/**
 * Defines a Kinesis Delivery Stream Logging Configuration.
 */
export class KinesisDataFirehoseLogLocation extends LogLocationBase {
  public readonly logType : LogType | string;
  public readonly logDestinationType : LogDestinationType | string;
  public readonly logDestination: { [key: string]: string };

  constructor(props:KinesisDataFirehoseLogLocationProps) {
    super(LogDestinationType.KINESISDATAFIREHOSE, props);
    this.logDestinationType = LogDestinationType.KINESISDATAFIREHOSE;
    this.logType = props.logType;

    // Throws and error if deliveryStream is invalid format.
    // skip validation for late-bound values.
    if ( !core.Token.isUnresolved(props.deliveryStream)) {
      if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(props.deliveryStream)) {
        // Throws and error if logGroup is invalid format.
        throw new Error(`'LogGroup' must have 1-64 characters of only letters, numbers, hyphens, dots (.), and underscores. Got: ${props.deliveryStream}`);
      }
    }

    this.logDestination = {
      deliveryStream: props.deliveryStream,
    };
  }
};

/**
 * Defines a Cloud Watch Log Group Logging Option.
 */
export interface CloudWatchLogLocationProps extends LogLocationProps{
  /**
   * The name of the CloudWatch Log Group to send logs to.
   */
  readonly logGroup: string;
};

/**
 * Defines a Cloud Watch Log Group Logging Configuration.
 */
export class CloudWatchLogLocation extends LogLocationBase {
  public readonly logType : LogType | string;
  public readonly logDestinationType : LogDestinationType | string;
  public readonly logDestination: { [key: string]: string };

  constructor(props:CloudWatchLogLocationProps) {
    super(LogDestinationType.CLOUDWATCH, props);
    this.logDestinationType = LogDestinationType.CLOUDWATCH;
    this.logType = props.logType;

    // skip validation for late-bound values.
    if ( !core.Token.isUnresolved(props.logGroup)) {
      if (!/^[a-zA-Z-_0-9/.#]{1,512}$/.test(props.logGroup)) {
        // Throws and error if logGroup is invalid format.
        throw new Error(`'LogGroup' must have 1-512 characters of only letters, numbers, hyphens, underscores, and pounds (#). Got: ${props.logGroup} `);
      }
    }

    this.logDestination = {
      logGroup: props.logGroup,
    };
  }
};

/**
  * Defines a Network Firewall Logging Configuration in the stack
  */
export interface ILoggingConfiguration extends core.IResource{
  /**
   * The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with.
   * You can't change the firewall specification after you create the logging configuration.
   *
   * @attribute
   */
  readonly firewallRef: string;
};

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
};

/**
 * Defines a Logging Configuration in the Stack
 * @resource AWS::NetworkFirewall::LoggingConfiguration
 */
export class LoggingConfiguration extends core.Resource implements ILoggingConfiguration {

  /**
   * The associated firewall Arn
   * @attribute
   */
  public readonly firewallRef: string;

  /**
   * The associated firewall Name
   * @attribute
   */
  public readonly firewallName?: string;

  /**
   * Defines how AWS Network Firewall performs logging for a Firewall.
   *
   */
  public loggingLocations: ILogLocation[];

  constructor(scope:Construct, id: string, props: LoggingConfigurationProps) {
    super(scope, id, {
      physicalName: props.loggingConfigurationName,
    });

    // skip validation for late-bound values.
    if (props.firewallName && !core.Token.isUnresolved(props.firewallName)) {
      if (!/^[a-zA-Z0-9-]{1,128}$/.test(props.firewallName)) {
        // Throws and error if logGroup is invalid format.
        throw new Error(`'FirewallName' must have 1-128 characters of only letters, numbers, and hyphens. Got: ${props.firewallName}`);
      }
    }

    this.firewallRef = props.firewallRef;
    this.firewallName = props.firewallName;
    this.loggingLocations = props.loggingLocations || [];

    const logDestinationConfigs:CfnLoggingConfiguration.LogDestinationConfigProperty[] =
    this.iLogLocationsToLogDestinationConfigProperty(this.loggingLocations);

    const loggingConfigurationProperty:CfnLoggingConfiguration.LoggingConfigurationProperty = {
      logDestinationConfigs: logDestinationConfigs,
    };
    const resourceProps:CfnLoggingConfigurationProps = {
      firewallArn: this.firewallRef,
      loggingConfiguration: loggingConfigurationProperty,
      firewallName: props.firewallName,
    };
    const resource:CfnLoggingConfiguration = new CfnLoggingConfiguration(scope, `${id}`, resourceProps);

    this.firewallRef = resource.firewallArn;
  }

  /**
   * Convert ILogLocation array to L1 LogDestinationConfigProperty array.
   * @param logLocations An array of assorted Log Locations
   * @returns Array of LogDestinationConfigProperty objects.
   */
  public iLogLocationsToLogDestinationConfigProperty(logLocations:ILogLocation[]):CfnLoggingConfiguration.LogDestinationConfigProperty[] {
    let logDestinationConfigs:CfnLoggingConfiguration.LogDestinationConfigProperty[] = [];
    let logLocation:ILogLocation;
    for (logLocation of logLocations) {
      logDestinationConfigs.push({
        logDestination: logLocation.logDestination,
        logDestinationType: logLocation.logDestinationType,
        logType: logLocation.logType,
      });
    }
    return logDestinationConfigs;
  }
};
