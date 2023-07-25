"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Firewall = void 0;
const logging_1 = require("./logging");
const aws_networkfirewall_1 = require("aws-cdk-lib/aws-networkfirewall");
const ec2 = require("aws-cdk-lib/aws-ec2");
const core = require("aws-cdk-lib/core");
/**
 * Defines a Network Firewall
 */
class FirewallBase extends core.Resource {
}
/**
 * Defines a Network Firewall in the Stack
 * @resource AWS::NetworkFirewall::Firewall
 */
class Firewall extends FirewallBase {
    /**
     * Reference an existing Network Firewall,
     * defined outside of the CDK code, by name.
     */
    static fromFirewallName(scope, id, firewallName) {
        if (core.Token.isUnresolved(firewallName)) {
            throw new Error('All arguments to Firewall.fromFirewallName must be concrete (no Tokens)');
        }
        class Import extends FirewallBase {
            constructor() {
                super(...arguments);
                this.firewallId = firewallName;
                // Since we have the name, we can generate the ARN,
                this.firewallArn = core.Stack.of(scope)
                    .formatArn({
                    service: 'network-firewall',
                    resource: 'firewall',
                    resourceName: firewallName,
                });
                //public readonly endpointIds = [''];
            }
        }
        return new Import(scope, id);
    }
    /**
     * Reference an existing Network Firewall,
     * defined outside of the CDK code, by arn.
     */
    static fromFirewallArn(scope, id, firewallArn) {
        if (core.Token.isUnresolved(firewallArn)) {
            throw new Error('All arguments to Firewall.fromFirewallArn must be concrete (no Tokens)');
        }
        class Import extends FirewallBase {
            constructor() {
                super(...arguments);
                this.firewallId = core.Fn.select(1, core.Fn.split('/', firewallArn));
                this.firewallArn = firewallArn;
                //public readonly endpointIds = [''];
            }
        }
        return new Import(scope, id);
    }
    constructor(scope, id, props) {
        super(scope, id, {
            physicalName: props.firewallName,
        });
        // Adding Validations
        /*
         * Validate firewallName
         */
        if (props.firewallName !== undefined &&
            !/^[a-zA-Z0-9-]{1,128}$/.test(props.firewallName)) {
            throw new Error('firewallName must be non-empty and contain only letters, numbers, and dashes, ' +
                `got: '${props.firewallName}'`);
        }
        // Auto define new policy?
        //const firewallPolicy:IfirewallPolicy = props.policy ||
        //		new policy(scope, id, {
        //				statelessDefaultActions: [StatelessStandardAction.FORWARD]
        //				statelessFragementDefaultActions: [StatelessStandardAction.FORWARD]
        //			}
        //		);
        // Auto pick subnetMappings from VPC if not provieded
        let subnets = [];
        if (props.subnetMappings !== undefined) {
            subnets = this.castSubnetMapping(props.subnetMappings);
        }
        else {
            let subnetMapping = props.vpc.selectSubnets({
                subnetType: ec2.SubnetType.PUBLIC,
            });
            subnets = this.castSubnetMapping(subnetMapping);
        }
        const resourceProps = {
            firewallName: props.firewallName || id,
            firewallPolicyArn: props.policy.firewallPolicyArn,
            subnetMappings: subnets,
            vpcId: props.vpc.vpcId,
            description: props.description,
            deleteProtection: props.deleteProtection,
            firewallPolicyChangeProtection: props.firewallPolicyChangeProtection,
            subnetChangeProtection: props.subnetChangeProtection,
            tags: props.tags || [],
        };
        const resource = new aws_networkfirewall_1.CfnFirewall(this, id, resourceProps);
        this.firewallId = this.getResourceNameAttribute(resource.ref);
        this.firewallArn = this.getResourceArnAttribute(resource.attrFirewallArn, {
            service: 'NetworkFirewall',
            resource: 'Firewall',
            resourceName: this.firewallId,
        });
        this.endpointIds = resource.attrEndpointIds;
        this.policy = props.policy;
        this.loggingConfigurations = [];
        this.loggingCloudWatchLogGroups = props.loggingCloudWatchLogGroups || [];
        this.loggingS3Buckets = props.loggingS3Buckets || [];
        this.loggingKinesisDataStreams = props.loggingKinesisDataStreams || [];
        let logLocations = [];
        if (props.loggingCloudWatchLogGroups) {
            //let cloudWatchLogGroups: ILogLocation[] = [];
            let cloudWatchLogGroup;
            for (cloudWatchLogGroup of props.loggingCloudWatchLogGroups) {
                const logLocation = new logging_1.CloudWatchLogLocation(cloudWatchLogGroup);
                //cloudWatchLogGroups.push(logLocation);
                logLocations.push(logLocation);
            }
            //this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-CloudWatch`, cloudWatchLogGroups));
        }
        if (props.loggingS3Buckets) {
            //let s3LogGroups: ILogLocation[] = [];
            let s3LogGroup;
            for (s3LogGroup of props.loggingS3Buckets) {
                const logLocation = new logging_1.S3LogLocation(s3LogGroup);
                //s3LogGroups.push(logLocation);
                logLocations.push(logLocation);
            }
            //this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-S3Buckets`, s3LogGroups));
        }
        if (props.loggingKinesisDataStreams) {
            //let kinesisLogGroups: ILogLocation[] = [];
            let kinesisLogGroup;
            for (kinesisLogGroup of props.loggingKinesisDataStreams) {
                const logLocation = new logging_1.KinesisDataFirehoseLogLocation(kinesisLogGroup);
                //kinesisLogGroups.push(logLocation);
                logLocations.push(logLocation);
            }
            //this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-logging-KinesisDataFirehose`, kinesisLogGroups));
        }
        this.loggingConfigurations.push(this.addLoggingConfigurations(`${id}-firewall-logging`, logLocations));
    }
    /**
     * Add a Logging Configuration to the Firewall.
     * @param configurationName The Name of the Logging configuration type.
     * @param logLocations An array of Log Locations.
     * @returns A LoggingConfiguration Resource.
     */
    addLoggingConfigurations(configurationName, logLocations) {
        return new logging_1.LoggingConfiguration(this, configurationName, {
            firewallRef: this.firewallArn,
            firewallName: this.physicalName,
            loggingConfigurationName: configurationName,
            loggingLocations: logLocations,
        });
    }
    /**
     * Cast SubnetSelection to a list ofsubnetMappingProperty
     */
    castSubnetMapping(subnetSelection) {
        let subnets = [];
        let subnet;
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
exports.Firewall = Firewall;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZmlyZXdhbGwuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJmaXJld2FsbC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSx1Q0FVbUI7QUFDbkIseUVBQWdGO0FBRWhGLDJDQUEyQztBQUMzQyx5Q0FBeUM7QUE2QnpDOztHQUVHO0FBQ0gsTUFBZSxZQUFhLFNBQVEsSUFBSSxDQUFDLFFBQVE7Q0FJaEQ7QUE2RkQ7OztHQUdHO0FBQ0gsTUFBYSxRQUFTLFNBQVEsWUFBWTtJQUV4Qzs7O09BR0c7SUFDSSxNQUFNLENBQUMsZ0JBQWdCLENBQUMsS0FBZ0IsRUFBRSxFQUFVLEVBQUUsWUFBb0I7UUFDL0UsSUFBSSxJQUFJLENBQUMsS0FBSyxDQUFDLFlBQVksQ0FBQyxZQUFZLENBQUMsRUFBRTtZQUN6QyxNQUFNLElBQUksS0FBSyxDQUFDLHlFQUF5RSxDQUFDLENBQUM7U0FDNUY7UUFFRCxNQUFNLE1BQU8sU0FBUSxZQUFZO1lBQWpDOztnQkFDa0IsZUFBVSxHQUFHLFlBQVksQ0FBQztnQkFDMUMsbURBQW1EO2dCQUNuQyxnQkFBVyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLEtBQUssQ0FBQztxQkFDL0MsU0FBUyxDQUFDO29CQUNULE9BQU8sRUFBRSxrQkFBa0I7b0JBQzNCLFFBQVEsRUFBRSxVQUFVO29CQUNwQixZQUFZLEVBQUUsWUFBWTtpQkFDM0IsQ0FBQyxDQUFDO2dCQUNMLHFDQUFxQztZQUN2QyxDQUFDO1NBQUE7UUFDRCxPQUFPLElBQUksTUFBTSxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBRUQ7OztPQUdHO0lBQ0ksTUFBTSxDQUFDLGVBQWUsQ0FBQyxLQUFnQixFQUFFLEVBQVUsRUFBRSxXQUFtQjtRQUM3RSxJQUFJLElBQUksQ0FBQyxLQUFLLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxFQUFFO1lBQ3hDLE1BQU0sSUFBSSxLQUFLLENBQUMsd0VBQXdFLENBQUMsQ0FB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LENBQUMsV0FBVyxDQUFDLENBQUM7YUFDaEM7WUFDRCx3SEFBd0g7U0FDekg7UUFFRCxJQUFJLENBQUMscUJBQXFCLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyx3QkFBd0IsQ0FBQyxHQUFHLEVBQUUsbUJBQW1CLEVBQUUsWUFBWSxDQUFDLENBQUMsQ0FBQztJQUN6RyxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSSx3QkFBd0IsQ0FBQyxpQkFBeUIsRUFBRSxZQUE0QjtRQUNyRixPQUFPLElBQUksOEJBQW9CLENBQUMsSUFBSSxFQUFFLGlCQUFpQixFQUFFO1lBQ3ZELFdBQVcsRUFBRSxJQUFJLENBQUMsV0FBVztZQUM3QixZQUFZLEVBQUUsSUFBSSxDQUFDLFlBQVk7WUFDL0Isd0JBQXdCLEVBQUUsaUJBQWlCO1lBQzNDLGdCQUFnQixFQUFFLFlBQVk7U0FDL0IsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztJQUVEOztPQUVHO0lBQ0ssaUJBQWlCLENBQUMsZUFBNkM7UUFDckUsSUFBSSxPQUFPLEdBQXFDLEVBQUUsQ0FBQztRQUNuRCxJQUFJLE1BQWtCLENBQUM7UUFDdkIsSUFBSSxlQUFlLEtBQUssU0FBUyxJQUFJLGVBQWUsQ0FBQyxPQUFPLEtBQUssU0FBUyxFQUFFO1lBQzFFLEtBQUssTUFBTSxJQUFJLGVBQWUsQ0FBQyxPQUFPLEVBQUU7Z0JBQ3RDLE9BQU8sQ0FBQyxJQUFJLENBQUM7b0JBQ1gsUUFBUSxFQUFFLE1BQU0sQ0FBQyxRQUFRO2lCQUMxQixDQUFDLENBQUM7YUFDSjtTQUNGO1FBQ0QsT0FBTyxPQUFPLENBQUM7SUFDakIsQ0FBQztDQUNGO0FBaE9ELDRCQWdPQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gJ2NvbnN0cnVjdHMnO1xuaW1wb3J0IHtcbiAgSUxvZ0xvY2F0aW9uLFxuICBTM0xvZ0xvY2F0aW9uUHJvcHMsXG4gIFMzTG9nTG9jYXRpb24sXG4gIEtpbmVzaXNEYXRhRmlyZWhvc2VMb2dMb2NhdGlvblByb3BzLFxuICBLaW5lc2lzRGF0YUZpcmVob3NlTG9nTG9jYXRpb24sXG4gIENsb3VkV2F0Y2hMb2dMb2NhdGlvblByb3BzLFxuICBDbG91ZFdhdGNoTG9nTG9jYXRpb24sXG4gIExvZ2dpbmdDb25maWd1cmF0aW9uLFxuICBJTG9nZ2luZ0NvbmZpZ3VyYXRpb24sXG59IGZyb20gJy4vbG9nZ2luZyc7XG5pbXBvcnQgeyBDZm5GaXJld2FsbCwgQ2ZuRmlyZXdhbGxQcm9wcyB9IGZyb20gJ2F3cy1jZGstbGliL2F3cy1uZXR3b3JrZmlyZXdhbGwnO1xuaW1wb3J0IHsgSUZpcmV3YWxsUG9saWN5IH0gZnJvbSAnLi9wb2xpY3knO1xuaW1wb3J0ICogYXMgZWMyIGZyb20gJ2F3cy1jZGstbGliL2F3cy1lYzInO1xuaW1wb3J0ICogYXMgY29yZSBmcm9tICdhd3MtY2RrLWxpYi9jb3JlJztcblxuLyoqXG4gKiBEZWZpbmVzIGEgTmV0d29yayBGaXJld2FsbCBpbiB0aGUgc3RhY2tcbiAqL1xuZXhwb3J0IGludGVyZmFjZSBJRmlyZXdhbGwgZXh0ZW5kcyBjb3JlLklSZXNvdXJjZXtcbiAgLyoqXG4gICAqIFRoZSBBcm4gb2YgdGhlIEZpcmV3YWxsLlxuICAgKlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICByZWFkb25seSBmaXJld2FsbEFybjogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgcGh5c2ljYWwgbmFtZSBvZiB0aGUgRmlyZXdhbGwuXG4gICAqXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHJlYWRvbmx5IGZpcmV3YWxsSWQ6IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHVuaXF1ZSBJRHMgb2YgdGhlIGZpcmV3YWxsIGVuZHBvaW50cyBmb3IgYWxsIG9mIHRoZSBzdWJuZXRzIHRoYXQgeW91IGF0dGFjaGVkIHRvIHRoZSBmaXJld2FsbC5cbiAgICogVGhlIHN1Ym5ldHMgYXJlIG5vdCBsaXN0ZWQgaW4gYW55IHBhcnRpY3VsYXIgb3JkZXIuXG4gICAqXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIC8vcmVhZG9ubHkgZW5kcG9pbnRJZHM6IHN0cmluZ1tdO1xufVxuXG4vKipcbiAqIERlZmluZXMgYSBOZXR3b3JrIEZpcmV3YWxsXG4gKi9cbmFic3RyYWN0IGNsYXNzIEZpcmV3YWxsQmFzZSBleHRlbmRzIGNvcmUuUmVzb3VyY2UgaW1wbGVtZW50cyBJRmlyZXdhbGwge1xuICBwdWJsaWMgYWJzdHJhY3QgcmVhZG9ubHkgZmlyZXdhbGxBcm46IHN0cmluZztcbiAgcHVibGljIGFic3RyYWN0IHJlYWRvbmx5IGZpcmV3YWxsSWQ6IHN0cmluZztcbiAgLy9wdWJsaWMgYWJzdHJhY3QgcmVhZG9ubHkgZW5kcG9pbnRJZHM6IHN0cmluZ1tdO1xufVxuXG4vKipcbiAqIFRoZSBQcm9wZXJ0aWVzIGZvciBkZWZpbmluZyBhIEZpcmV3YWxsIFJlc291cmNlXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRmlyZXdhbGxQcm9wcyB7XG4gIC8qKlxuICAgKiBUaGUgZGVzY3JpcHRpdmUgbmFtZSBvZiB0aGUgZmlyZXdhbGwuXG4gICAqIFlvdSBjYW4ndCBjaGFuZ2UgdGhlIG5hbWUgb2YgYSBmaXJld2FsbCBhZnRlciB5b3UgY3JlYXRlIGl0LlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIENsb3VkRm9ybWF0aW9uLWdlbmVyYXRlZCBuYW1lXG4gICAqL1xuICByZWFkb25seSBmaXJld2FsbE5hbWU/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIFRoZSB1bmlxdWUgaWRlbnRpZmllciBvZiB0aGUgVlBDIHdoZXJlIHRoZSBmaXJld2FsbCBpcyBpbiB1c2UuIFlvdSBjYW4ndCBjaGFuZ2UgdGhlIFZQQyBvZiBhIGZpcmV3YWxsIGFmdGVyIHlvdSBjcmVhdGUgdGhlIGZpcmV3YWxsLlxuICAgKlxuICAgKi9cbiAgcmVhZG9ubHkgdnBjOiBlYzIuSVZwYztcblxuICAvKipcbiAgICogRWFjaCBmaXJld2FsbCByZXF1aXJlcyBvbmUgZmlyZXdhbGwgcG9saWN5IGFzc29jaWF0aW9uLCBhbmQgeW91IGNhbiB1c2UgdGhlIHNhbWUgZmlyZXdhbGwgcG9saWN5IGZvciBtdWx0aXBsZSBmaXJld2FsbHMuXG4gICAqXG4gICAqL1xuICByZWFkb25seSBwb2xpY3k6IElGaXJld2FsbFBvbGljeTtcblxuICAvKipcbiAgICogVGhlIHB1YmxpYyBzdWJuZXRzIHRoYXQgTmV0d29yayBGaXJld2FsbCBpcyB1c2luZyBmb3IgdGhlIGZpcmV3YWxsLiBFYWNoIHN1Ym5ldCBtdXN0IGJlbG9uZyB0byBhIGRpZmZlcmVudCBBdmFpbGFiaWxpdHkgWm9uZS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBBbGwgcHVibGljIHN1Ym5ldHMgb2YgdGhlIFZQQ1xuICAgKi9cbiAgcmVhZG9ubHkgc3VibmV0TWFwcGluZ3M/OiBlYzIuU3VibmV0U2VsZWN0aW9uO1xuXG4gIC8qKlxuICAgKiBUaGUgZGVzY3JpcHRpb25nIG9mIHRoZSBGaXJld2FsbFxuICAgKlxuICAgKiBAZGVmYXVsdCAtIHVuZGVmaW5lZFxuICAgKi9cbiAgcmVhZG9ubHkgZGVzY3JpcHRpb24/OiBzdHJpbmc7XG5cbiAgLyoqXG4gICAqIEEgZmxhZyBpbmRpY2F0aW5nIHdoZXRoZXIgaXQgaXMgcG9zc2libGUgdG8gZGVsZXRlIHRoZSBmaXJld2FsbC5cbiAgICogQSBzZXR0aW5nIG9mIFRSVUUgaW5kaWNhdGVzIHRoYXQgdGhlIGZpcmV3YWxsIGlzIHByb3RlY3RlZCBhZ2FpbnN0IGRlbGV0aW9uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gdHJ1ZVxuICAgKi9cbiAgcmVhZG9ubHkgZGVsZXRlUHJvdGVjdGlvbj86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIEEgc2V0dGluZyBpbmRpY2F0aW5nIHdoZXRoZXIgdGhlIGZpcmV3YWxsIGlzIHByb3RlY3RlZCBhZ2FpbnN0IGEgY2hhbmdlIHRvIHRoZSBmaXJld2FsbCBwb2xpY3kgYXNzb2NpYXRpb24uXG4gICAqIFVzZSB0aGlzIHNldHRpbmcgdG8gcHJvdGVjdCBhZ2FpbnN0IGFjY2lkZW50YWxseSBtb2RpZnlpbmcgdGhlIGZpcmV3YWxsIHBvbGljeSBmb3IgYSBmaXJld2FsbCB0aGF0IGlzIGluIHVzZS5cbiAgICpcbiAgICogQGRlZmF1bHQgLSB0cnVlXG4gICAqL1xuICByZWFkb25seSBmaXJld2FsbFBvbGljeUNoYW5nZVByb3RlY3Rpb24/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBBIHNldHRpbmcgaW5kaWNhdGluZyB3aGV0aGVyIHRoZSBmaXJld2FsbCBpcyBwcm90ZWN0ZWQgYWdhaW5zdCBjaGFuZ2VzIHRvIHRoZSBzdWJuZXQgYXNzb2NpYXRpb25zLlxuICAgKiBVc2UgdGhpcyBzZXR0aW5nIHRvIHByb3RlY3QgYWdhaW5zdCBhY2NpZGVudGFsbHkgbW9kaWZ5aW5nIHRoZSBzdWJuZXQgYXNzb2NpYXRpb25zIGZvciBhIGZpcmV3YWxsIHRoYXQgaXMgaW4gdXNlLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIHRydWVcbiAgICovXG4gIHJlYWRvbmx5IHN1Ym5ldENoYW5nZVByb3RlY3Rpb24/OiBib29sZWFuO1xuXG4gIC8qKlxuICAgKiBUYWdzIHRvIGJlIGFkZGVkIHRvIHRoZSBmaXJld2FsbC5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBObyB0YWdzIGFwcGxpZWRcbiAgICovXG4gIHJlYWRvbmx5IHRhZ3M/OiBjb3JlLlRhZ1tdO1xuXG4gIC8qKlxuICAgKiBBIGxpc3Qgb2YgQ2xvdWRXYXRjaCBMb2dHcm91cHMgdG8gc2VuZCBsb2dzIHRvLlxuICAgKlxuICAgKiBAZGVmYXVsdCAtIExvZ3Mgd2lsbCBub3QgYmUgc2VudCB0byBhIGNsb3Vkd2F0Y2ggZ3JvdXAuXG4gICAqL1xuICByZWFkb25seSBsb2dnaW5nQ2xvdWRXYXRjaExvZ0dyb3Vwcz86IENsb3VkV2F0Y2hMb2dMb2NhdGlvblByb3BzW107XG5cbiAgLyoqXG4gICAqIEEgbGlzdCBvZiBTMyBCdWNrZXRzIHRvIHNlbmQgbG9ncyB0by5cbiAgICpcbiAgICogQGRlZmF1bHQgLSBMb2dzIHdpbGwgbm90IGJlIHNlbnQgdG8gYW4gUzMgYnVja2V0LlxuICAgKi9cbiAgcmVhZG9ubHkgbG9nZ2luZ1MzQnVja2V0cz86IFMzTG9nTG9jYXRpb25Qcm9wc1tdO1xuXG4gIC8qKlxuICAgKiBBIGxpc3Qgb2YgUzMgQnVja2V0cyB0byBzZW5kIGxvZ3MgdG8uXG4gICAqXG4gICAqIEBkZWZhdWx0IC0gTG9ncyB3aWxsIG5vdCBiZSBzZW50IHRvIGFuIFMzIGJ1Y2tldC5cbiAgICovXG4gIHJlYWRvbmx5IGxvZ2dpbmdLaW5lc2lzRGF0YVN0cmVhbXM/OiBLaW5lc2lzRGF0YUZpcmVob3NlTG9nTG9jYXRpb25Qcm9wc1tdO1xufVxuXG4vKipcbiAqIERlZmluZXMgYSBOZXR3b3JrIEZpcmV3YWxsIGluIHRoZSBTdGFja1xuICogQHJlc291cmNlIEFXUzo6TmV0d29ya0ZpcmV3YWxsOjpGaXJld2FsbFxuICovXG5leHBvcnQgY2xhc3MgRmlyZXdhbGwgZXh0ZW5kcyBGaXJld2FsbEJhc2Uge1xuXG4gIC8qKlxuICAgKiBSZWZlcmVuY2UgYW4gZXhpc3RpbmcgTmV0d29yayBGaXJld2FsbCxcbiAgICogZGVmaW5lZCBvdXRzaWRlIG9mIHRoZSBDREsgY29kZSwgYnkgbmFtZS5cbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgZnJvbUZpcmV3YWxsTmFtZShzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBmaXJld2FsbE5hbWU6IHN0cmluZyk6IElGaXJld2FsbCB7XG4gICAgaWYgKGNvcmUuVG9rZW4uaXNVbnJlc29sdmVkKGZpcmV3YWxsTmFtZSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxsIGFyZ3VtZW50cyB0byBGaXJld2FsbC5mcm9tRmlyZXdhbGxOYW1lIG11c3QgYmUgY29uY3JldGUgKG5vIFRva2VucyknKTtcbiAgICB9XG5cbiAgICBjbGFzcyBJbXBvcnQgZXh0ZW5kcyBGaXJld2FsbEJhc2Uge1xuICAgICAgcHVibGljIHJlYWRvbmx5IGZpcmV3YWxsSWQgPSBmaXJld2FsbE5hbWU7XG4gICAgICAvLyBTaW5jZSB3ZSBoYXZlIHRoZSBuYW1lLCB3ZSBjYW4gZ2VuZXJhdGUgdGhlIEFSTixcbiAgICAgIHB1YmxpYyByZWFkb25seSBmaXJld2FsbEFybiA9IGNvcmUuU3RhY2sub2Yoc2NvcGUpXG4gICAgICAgIC5mb3JtYXRBcm4oe1xuICAgICAgICAgIHNlcnZpY2U6ICduZXR3b3JrLWZpcmV3YWxsJyxcbiAgICAgICAgICByZXNvdXJjZTogJ2ZpcmV3YWxsJyxcbiAgICAgICAgICByZXNvdXJjZU5hbWU6IGZpcmV3YWxsTmFtZSxcbiAgICAgICAgfSk7XG4gICAgICAvL3B1YmxpYyByZWFkb25seSBlbmRwb2ludElkcyA9IFsnJ107XG4gICAgfVxuICAgIHJldHVybiBuZXcgSW1wb3J0KHNjb3BlLCBpZCk7XG4gIH1cblxuICAvKipcbiAgICogUmVmZXJlbmNlIGFuIGV4aXN0aW5nIE5ldHdvcmsgRmlyZXdhbGwsXG4gICAqIGRlZmluZWQgb3V0c2lkZSBvZiB0aGUgQ0RLIGNvZGUsIGJ5IGFybi5cbiAgICovXG4gIHB1YmxpYyBzdGF0aWMgZnJvbUZpcmV3YWxsQXJuKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIGZpcmV3YWxsQXJuOiBzdHJpbmcpOiBJRmlyZXdhbGwge1xuICAgIGlmIChjb3JlLlRva2VuLmlzVW5yZXNvbHZlZChmaXJld2FsbEFybikpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxsIGFyZ3VtZW50cyB0byBGaXJld2FsbC5mcm9tRmlyZXdhbGxBcm4gbXVzdCBiZSBjb25jcmV0ZSAobm8gVG9rZW5zKScpO1xuICAgIH1cbiAgICBjbGFzcyBJbXBvcnQgZXh0ZW5kcyBGaXJld2FsbEJhc2Uge1xuICAgICAgcHVibGljIHJlYWRvbmx5IGZpcmV3YWxsSWQgPSBjb3JlLkZuLnNlbGVjdCgxLCBjb3JlLkZuLnNwbGl0KCcvJywgZmlyZXdhbGxBcm4pKTtcbiAgICAgIHB1YmxpYyByZWFkb25seSBmaXJld2FsbEFybiA9IGZpcmV3YWxsQXJuO1xuICAgICAgLy9wdWJsaWMgcmVhZG9ubHkgZW5kcG9pbnRJZHMgPSBbJyddO1xuICAgIH1cbiAgICByZXR1cm4gbmV3IEltcG9ydChzY29wZSwgaWQpO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoZSBBcm4gb2YgdGhlIEZpcmV3YWxsLlxuICAgKlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgZmlyZXdhbGxBcm46IHN0cmluZztcblxuICAvKipcbiAgICogVGhlIHBoeXNpY2FsIG5hbWUgb2YgdGhlIEZpcmV3YWxsLlxuICAgKlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICBwdWJsaWMgcmVhZG9ubHkgZmlyZXdhbGxJZDogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBUaGUgdW5pcXVlIElEcyBvZiB0aGUgZmlyZXdhbGwgZW5kcG9pbnRzIGZvciBhbGwgb2YgdGhlIHN1Ym5ldHMgdGhhdCB5b3UgYXR0YWNoZWQgdG8gdGhlIGZpcmV3YWxsLlxuICAgKiBUaGUgc3VibmV0cyBhcmUgbm90IGxpc3RlZCBpbiBhbnkgcGFydGljdWxhciBvcmRlci5cbiAgICpcbiAgICogQGF0dHJpYnV0ZVxuICAgKi9cbiAgcHVibGljIHJlYWRvbmx5IGVuZHBvaW50SWRzOiBzdHJpbmdbXTtcblxuICAvKipcbiAgICogVGhlIGFzc29jaWF0ZWQgZmlyZXdhbGwgUG9saWN5XG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHB1YmxpYyByZWFkb25seSBwb2xpY3k6IElGaXJld2FsbFBvbGljeTtcblxuICAvKipcbiAgICogVGhlIENsb3VkIFdhdGNoIExvZyBHcm91cHMgdG8gc2VuZCBsb2dzIHRvLlxuICAgKiBAYXR0cmlidXRlXG4gICAqL1xuICBwdWJsaWMgbG9nZ2luZ0Nsb3VkV2F0Y2hMb2dHcm91cHM6IENsb3VkV2F0Y2hMb2dMb2NhdGlvblByb3BzW107XG5cbiAgLyoqXG4gICAqIFRoZSBTMyBCdWNrZXRzIHRvIHNlbmQgbG9ncyB0by5cbiAgICogQGF0dHJpYnV0ZVxuICAgKi9cbiAgcHVibGljIGxvZ2dpbmdTM0J1Y2tldHM6IFMzTG9nTG9jYXRpb25Qcm9wc1tdO1xuXG4gIC8qKlxuICAgKiBUaGUgS2luZXNpcyBEYXRhIFN0cmVhbSBsb2NhdGlvbnMuXG4gICAqIEBhdHRyaWJ1dGVcbiAgICovXG4gIHB1YmxpYyBsb2dnaW5nS2luZXNpc0RhdGFTdHJlYW1zOiBLaW5lc2lzRGF0YUZpcmVob3NlTG9nTG9jYXRpb25Qcm9wc1tdO1xuXG4gIC8qKlxuICAqIFRoZSBsaXN0IG9mIHJlZmVyZW5jZXMgdG8gdGhlIGdlbmVyYXRlZCBsb2dnaW5nIGNvbmZpZ3VyYXRpb25zLlxuICAqL1xuICBwdWJsaWMgbG9nZ2luZ0NvbmZpZ3VyYXRpb25zOiBJTG9nZ2luZ0NvbmZpZ3VyYXRpb25bXTtcblxuICBjb25zdHJ1Y3RvcihzY29wZTpDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBGaXJld2FsbFByb3BzKSB7XG4gICAgc3VwZXIoc2NvcGUsIGlkLCB7XG4gICAgICBwaHlzaWNhbE5hbWU6IHByb3BzLmZpcmV3YWxsTmFtZSxcbiAgICB9KTtcblxuICAgIC8vIEFkZGluZyBWYWxpZGF0aW9uc1xuXG4gICAgLypcbiAgICAgKiBWYWxpZGF0ZSBmaXJld2FsbE5hbWVcbiAgICAgKi9cbiAgICBpZiAocHJvcHMuZmlyZXdhbGxOYW1lICE9PSB1bmRlZmluZWQgJiZcblx0XHRcdFx0IS9eW2EtekEtWjAtOS1dezEsMTI4fSQvLnRlc3QocHJvcHMuZmlyZXdhbGxOYW1lKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdmaXJld2FsbE5hbWUgbXVzdCBiZSBub24tZW1wdHkgYW5kIGNvbnRhaW4gb25seSBsZXR0ZXJzLCBudW1iZXJzLCBhbmQgZGFzaGVzLCAnICtcblx0XHRcdFx0YGdvdDogJyR7cHJvcHMuZmlyZXdhbGxOYW1lfSdgKTtcbiAgICB9XG5cbiAgICAvLyBBdXRvIGRlZmluZSBuZXcgcG9saWN5P1xuICAgIC8vY29uc3QgZmlyZXdhbGxQb2xpY3k6SWZpcmV3YWxsUG9saWN5ID0gcHJvcHMucG9saWN5IHx8XG4gICAgLy9cdFx0bmV3IHBvbGljeShzY29wZSwgaWQsIHtcbiAgICAvL1x0XHRcdFx0c3RhdGVsZXNzRGVmYXVsdEFjdGlvbnM6IFtTdGF0ZWxlc3NTdGFuZGFyZEFjdGlvbi5GT1JXQVJEXVxuICAgIC8vXHRcdFx0XHRzdGF0ZWxlc3NGcmFnZW1lbnREZWZhdWx0QWN0aW9uczogW1N0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkZPUldBUkRdXG4gICAgLy9cdFx0XHR9XG4gICAgLy9cdFx0KTtcblxuICAgIC8vIEF1dG8gcGljayBzdWJuZXRNYXBwaW5ncyBmcm9tIFZQQyBpZiBub3QgcHJvdmllZGVkXG4gICAgbGV0IHN1Ym5ldHM6Q2ZuRmlyZXdhbGwuU3VibmV0TWFwcGluZ1Byb3BlcnR5W109W107XG4gICAgaWYgKHByb3BzLnN1Ym5ldE1hcHBpbmdzICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIHN1Ym5ldHMgPSB0aGlzLmNhc3RTdWJuZXRNYXBwaW5nKHByb3BzLnN1Ym5ldE1hcHBpbmdzKTtcbiAgICB9IGVsc2Uge1xuICAgICAgbGV0IHN1Ym5ldE1hcHBpbmc6ZWMyLlN1Ym5ldFNlbGVjdGlvbiA9IHByb3BzLnZwYy5zZWxlY3RTdWJuZXRzKHtcbiAgICAgICAgc3VibmV0VHlwZTogZWMyLlN1Ym5ldFR5cGUuUFVCTElDLFxuICAgICAgfSk7XG4gICAgICBzdWJuZXRzID0gdGhpcy5jYXN0U3VibmV0TWFwcGluZyhzdWJuZXRNYXBwaW5nKTtcbiAgICB9XG5cbiAgICBjb25zdCByZXNvdXJjZVByb3BzOkNmbkZpcmV3YWxsUHJvcHMgPSB7XG4gICAgICBmaXJld2FsbE5hbWU6IHByb3BzLmZpcmV3YWxsTmFtZXx8aWQsXG4gICAgICBmaXJld2FsbFBvbGljeUFybjogcHJvcHMucG9saWN5LmZpcmV3YWxsUG9saWN5QXJuLFxuICAgICAgc3VibmV0TWFwcGluZ3M6IHN1Ym5ldHMsXG4gICAgICB2cGNJZDogcHJvcHMudnBjLnZwY0lkLFxuICAgICAgZGVzY3JpcHRpb246IHByb3BzLmRlc2NyaXB0aW9uLFxuICAgICAgZGVsZXRlUHJvdGVjdGlvbjogcHJvcHMuZGVsZXRlUHJvdGVjdGlvbixcbiAgICAgIGZpcmV3YWxsUG9saWN5Q2hhbmdlUHJvdGVjdGlvbjogcHJvcHMuZmlyZXdhbGxQb2xpY3lDaGFuZ2VQcm90ZWN0aW9uLFxuICAgICAgc3VibmV0Q2hhbmdlUHJvdGVjdGlvbjogcHJvcHMuc3VibmV0Q2hhbmdlUHJvdGVjdGlvbixcbiAgICAgIHRhZ3M6IHByb3BzLnRhZ3MgfHwgW10sXG4gICAgfTtcblxuICAgIGNvbnN0IHJlc291cmNlOkNmbkZpcmV3YWxsID0gbmV3IENmbkZpcmV3YWxsKHRoaXMsIGlkLCByZXNvdXJjZVByb3BzKTtcblxuICAgIHRoaXMuZmlyZXdhbGxJZCA9IHRoaXMuZ2V0UmVzb3VyY2VOYW1lQXR0cmlidXRlKHJlc291cmNlLnJlZik7XG4gICAgdGhpcy5maXJld2FsbEFybiA9IHRoaXMuZ2V0UmVzb3VyY2VBcm5BdHRyaWJ1dGUocmVzb3VyY2UuYXR0ckZpcmV3YWxsQXJuLCB7XG4gICAgICBzZXJ2aWNlOiAnTmV0d29ya0ZpcmV3YWxsJyxcbiAgICAgIHJlc291cmNlOiAnRmlyZXdhbGwnLFxuICAgICAgcmVzb3VyY2VOYW1lOiB0aGlzLmZpcmV3YWxsSWQsXG4gICAgfSk7XG5cbiAgICB0aGlzLmVuZHBvaW50SWRzID0gcmVzb3VyY2UuYXR0ckVuZHBvaW50SWRzO1xuICAgIHRoaXMucG9saWN5ID0gcHJvcHMucG9saWN5O1xuXG4gICAgdGhpcy5sb2dnaW5nQ29uZmlndXJhdGlvbnMgPSBbXTtcbiAgICB0aGlzLmxvZ2dpbmdDbG91ZFdhdGNoTG9nR3JvdXBzID0gcHJvcHMubG9nZ2luZ0Nsb3VkV2F0Y2hMb2dHcm91cHMgfHwgW107XG4gICAgdGhpcy5sb2dnaW5nUzNCdWNrZXRzID0gcHJvcHMubG9nZ2luZ1MzQnVja2V0cyB8fCBbXTtcbiAgICB0aGlzLmxvZ2dpbmdLaW5lc2lzRGF0YVN0cmVhbXMgPSBwcm9wcy5sb2dnaW5nS2luZXNpc0RhdGFTdHJlYW1zIHx8IFtdO1xuXG4gICAgbGV0IGxvZ0xvY2F0aW9uczogSUxvZ0xvY2F0aW9uW10gPSBbXTtcblxuICAgIGlmIChwcm9wcy5sb2dnaW5nQ2xvdWRXYXRjaExvZ0dyb3Vwcykge1xuICAgICAgLy9sZXQgY2xvdWRXYXRjaExvZ0dyb3VwczogSUxvZ0xvY2F0aW9uW10gPSBbXTtcbiAgICAgIGxldCBjbG91ZFdhdGNoTG9nR3JvdXA6Q2xvdWRXYXRjaExvZ0xvY2F0aW9uUHJvcHM7XG4gICAgICBmb3IgKGNsb3VkV2F0Y2hMb2dHcm91cCBvZiBwcm9wcy5sb2dnaW5nQ2xvdWRXYXRjaExvZ0dyb3Vwcykge1xuICAgICAgICBjb25zdCBsb2dMb2NhdGlvbjpJTG9nTG9jYXRpb24gPSBuZXcgQ2xvdWRXYXRjaExvZ0xvY2F0aW9uKGNsb3VkV2F0Y2hMb2dHcm91cCk7XG4gICAgICAgIC8vY2xvdWRXYXRjaExvZ0dyb3Vwcy5wdXNoKGxvZ0xvY2F0aW9uKTtcbiAgICAgICAgbG9nTG9jYXRpb25zLnB1c2gobG9nTG9jYXRpb24pO1xuICAgICAgfVxuICAgICAgLy90aGlzLmxvZ2dpbmdDb25maWd1cmF0aW9ucy5wdXNoKHRoaXMuYWRkTG9nZ2luZ0NvbmZpZ3VyYXRpb25zKGAke2lkfS1sb2dnaW5nLUNsb3VkV2F0Y2hgLCBjbG91ZFdhdGNoTG9nR3JvdXBzKSk7XG4gICAgfVxuXG4gICAgaWYgKHByb3BzLmxvZ2dpbmdTM0J1Y2tldHMpIHtcbiAgICAgIC8vbGV0IHMzTG9nR3JvdXBzOiBJTG9nTG9jYXRpb25bXSA9IFtdO1xuICAgICAgbGV0IHMzTG9nR3JvdXA6UzNMb2dMb2NhdGlvblByb3BzO1xuICAgICAgZm9yIChzM0xvZ0dyb3VwIG9mIHByb3BzLmxvZ2dpbmdTM0J1Y2tldHMpIHtcbiAgICAgICAgY29uc3QgbG9nTG9jYXRpb246SUxvZ0xvY2F0aW9uID0gbmV3IFMzTG9nTG9jYXRpb24oczNMb2dHcm91cCk7XG4gICAgICAgIC8vczNMb2dHcm91cHMucHVzaChsb2dMb2NhdGlvbik7XG4gICAgICAgIGxvZ0xvY2F0aW9ucy5wdXNoKGxvZ0xvY2F0aW9uKTtcbiAgICAgIH1cbiAgICAgIC8vdGhpcy5sb2dnaW5nQ29uZmlndXJhdGlvbnMucHVzaCh0aGlzLmFkZExvZ2dpbmdDb25maWd1cmF0aW9ucyhgJHtpZH0tbG9nZ2luZy1TM0J1Y2tldHNgLCBzM0xvZ0dyb3VwcykpO1xuICAgIH1cblxuICAgIGlmIChwcm9wcy5sb2dnaW5nS2luZXNpc0RhdGFTdHJlYW1zKSB7XG4gICAgICAvL2xldCBraW5lc2lzTG9nR3JvdXBzOiBJTG9nTG9jYXRpb25bXSA9IFtdO1xuICAgICAgbGV0IGtpbmVzaXNMb2dHcm91cDogS2luZXNpc0RhdGFGaXJlaG9zZUxvZ0xvY2F0aW9uUHJvcHM7XG4gICAgICBmb3IgKGtpbmVzaXNMb2dHcm91cCBvZiBwcm9wcy5sb2dnaW5nS2luZXNpc0RhdGFTdHJlYW1zKSB7XG4gICAgICAgIGNvbnN0IGxvZ0xvY2F0aW9uOklMb2dMb2NhdGlvbiA9IG5ldyBLaW5lc2lzRGF0YUZpcmVob3NlTG9nTG9jYXRpb24oa2luZXNpc0xvZ0dyb3VwKTtcbiAgICAgICAgLy9raW5lc2lzTG9nR3JvdXBzLnB1c2gobG9nTG9jYXRpb24pO1xuICAgICAgICBsb2dMb2NhdGlvbnMucHVzaChsb2dMb2NhdGlvbik7XG4gICAgICB9XG4gICAgICAvL3RoaXMubG9nZ2luZ0NvbmZpZ3VyYXRpb25zLnB1c2godGhpcy5hZGRMb2dnaW5nQ29uZmlndXJhdGlvbnMoYCR7aWR9LWxvZ2dpbmctS2luZXNpc0RhdGFGaXJlaG9zZWAsIGtpbmVzaXNMb2dHcm91cHMpKTtcbiAgICB9XG5cbiAgICB0aGlzLmxvZ2dpbmdDb25maWd1cmF0aW9ucy5wdXNoKHRoaXMuYWRkTG9nZ2luZ0NvbmZpZ3VyYXRpb25zKGAke2lkfS1maXJld2FsbC1sb2dnaW5nYCwgbG9nTG9jYXRpb25zKSk7XG4gIH1cblxuICAvKipcbiAgICogQWRkIGEgTG9nZ2luZyBDb25maWd1cmF0aW9uIHRvIHRoZSBGaXJld2FsbC5cbiAgICogQHBhcmFtIGNvbmZpZ3VyYXRpb25OYW1lIFRoZSBOYW1lIG9mIHRoZSBMb2dnaW5nIGNvbmZpZ3VyYXRpb24gdHlwZS5cbiAgICogQHBhcmFtIGxvZ0xvY2F0aW9ucyBBbiBhcnJheSBvZiBMb2cgTG9jYXRpb25zLlxuICAgKiBAcmV0dXJucyBBIExvZ2dpbmdDb25maWd1cmF0aW9uIFJlc291cmNlLlxuICAgKi9cbiAgcHVibGljIGFkZExvZ2dpbmdDb25maWd1cmF0aW9ucyhjb25maWd1cmF0aW9uTmFtZTogc3RyaW5nLCBsb2dMb2NhdGlvbnM6IElMb2dMb2NhdGlvbltdKSB7XG4gICAgcmV0dXJuIG5ldyBMb2dnaW5nQ29uZmlndXJhdGlvbih0aGlzLCBjb25maWd1cmF0aW9uTmFtZSwge1xuICAgICAgZmlyZXdhbGxSZWY6IHRoaXMuZmlyZXdhbGxBcm4sXG4gICAgICBmaXJld2FsbE5hbWU6IHRoaXMucGh5c2ljYWxOYW1lLFxuICAgICAgbG9nZ2luZ0NvbmZpZ3VyYXRpb25OYW1lOiBjb25maWd1cmF0aW9uTmFtZSxcbiAgICAgIGxvZ2dpbmdMb2NhdGlvbnM6IGxvZ0xvY2F0aW9ucyxcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDYXN0IFN1Ym5ldFNlbGVjdGlvbiB0byBhIGxpc3Qgb2ZzdWJuZXRNYXBwaW5nUHJvcGVydHlcbiAgICovXG4gIHByaXZhdGUgY2FzdFN1Ym5ldE1hcHBpbmcoc3VibmV0U2VsZWN0aW9uOmVjMi5TdWJuZXRTZWxlY3Rpb258dW5kZWZpbmVkKTpDZm5GaXJld2FsbC5TdWJuZXRNYXBwaW5nUHJvcGVydHlbXSB7XG4gICAgbGV0IHN1Ym5ldHM6Q2ZuRmlyZXdhbGwuU3VibmV0TWFwcGluZ1Byb3BlcnR5W109W107XG4gICAgbGV0IHN1Ym5ldDplYzIuSVN1Ym5ldDtcbiAgICBpZiAoc3VibmV0U2VsZWN0aW9uICE9PSB1bmRlZmluZWQgJiYgc3VibmV0U2VsZWN0aW9uLnN1Ym5ldHMgIT09IHVuZGVmaW5lZCkge1xuICAgICAgZm9yIChzdWJuZXQgb2Ygc3VibmV0U2VsZWN0aW9uLnN1Ym5ldHMpIHtcbiAgICAgICAgc3VibmV0cy5wdXNoKHtcbiAgICAgICAgICBzdWJuZXRJZDogc3VibmV0LnN1Ym5ldElkLFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHN1Ym5ldHM7XG4gIH1cbn1cbiJdfQ==