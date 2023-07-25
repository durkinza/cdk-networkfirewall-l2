"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
//import { IntegTest } from 'aws-cdk-lib/integ-tests-alpha';
const ec2 = require("aws-cdk-lib/aws-ec2");
const s3 = require("aws-cdk-lib/aws-s3");
const cdk = require("aws-cdk-lib/core");
const NetFW = require("../lib");
class TestStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        const vpc = new ec2.Vpc(this, 'MyTestVpc', {
            ipAddresses: ec2.IpAddresses.cidr('10.0.0.0/16'),
        });
        // Setting up logging locations
        // const cloudWatchLogGroup = new logs.LogGroup(this, 'MyFirewallLogGroup');
        const s3LoggingBucket = new s3.Bucket(this, 'MyFirewallLogBucket');
        // const kinesisStream = new kinesis.Stream(this, 'MyFirewallStream', {
        //   streamName: 'my-test-stream',
        // });
        // Setup Stateful 5Tuple rule & Group
        const stateful5TupleRule = new NetFW.Stateful5TupleRule({
            action: NetFW.StatefulStandardAction.DROP,
            destinationPort: '$WEB_PORTS',
            destination: '$HOME_NET',
            protocol: 'TCP',
            sourcePort: 'any',
            source: '10.10.0.0/16',
            direction: NetFW.Stateful5TupleDirection.FORWARD,
            ruleOptions: [
                {
                    keyword: 'sid',
                    settings: ['1234'],
                },
            ],
        });
        const stateful5TupleRuleGroup = new NetFW.Stateful5TupleRuleGroup(this, 'MyStateful5TupleRuleGroup', {
            capacity: 100,
            rules: [stateful5TupleRule],
            variables: {
                ipSets: {
                    HOME_NET: { definition: ['10.0.0.0/16', '10.10.0.0/16'] },
                },
                portSets: {
                    WEB_PORTS: { definition: ['443', '80'] },
                },
            },
        });
        // Setup Stateful Domain list rule & Group
        const statefulDomainListRule = new NetFW.StatefulDomainListRule({
            type: NetFW.StatefulDomainListType.DENYLIST,
            targets: ['.example.com', 'www.example.org'],
            targetTypes: [
                NetFW.StatefulDomainListTargetType.TLS_SNI,
                NetFW.StatefulDomainListTargetType.HTTP_HOST,
            ],
        });
        const statefulDomainListRuleGroup = new NetFW.StatefulDomainListRuleGroup(this, 'MyStatefulDomainListRuleGroup', {
            capacity: 100,
            rule: statefulDomainListRule,
        });
        // Setup Stateful Suricata rule & Group
        const statefulSuricataRuleGroup = new NetFW.StatefulSuricataRuleGroup(this, 'MyStatefulSuricataRuleGroup', {
            capacity: 100,
            rules: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\".htpasswd access attempt\"; flow:to_server,established; content:\".htpasswd\"; nocase; sid:210503; rev:1;)',
            variables: {
                ipSets: {
                    HTTP_SERVERS: { definition: ['10.0.0.0/16'] },
                },
                portSets: {
                    HTTP_PORTS: { definition: ['80', '8080'] },
                },
            },
        });
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
            destinations: ['10.0.0.0/16'],
            protocols: [6],
            sourcePorts: [{
                    fromPort: 0,
                    toPort: 65535,
                }],
            sources: ['10.0.0.0/16', '10.10.0.0/16'],
        });
        const statelessRuleGroup = new NetFW.StatelessRuleGroup(this, 'MyStatelessRuleGroup', {
            ruleGroupName: 'MyStatelessRuleGroup',
            rules: [{ rule: statelessRule, priority: 10 }],
        });
        // Finally setup Policy and firewall.
        const policy = new NetFW.FirewallPolicy(this, 'MyNetworkfirewallPolicy', {
            statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
            statefulRuleGroups: [
                {
                    ruleGroup: statefulDomainListRuleGroup,
                },
                {
                    ruleGroup: stateful5TupleRuleGroup,
                },
                {
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
        new NetFW.Firewall(this, 'networkFirewall', {
            firewallName: 'my-network-firewall',
            vpc: vpc,
            policy: policy,
            // loggingCloudWatchLogGroups: [{
            //   logGroup: cloudWatchLogGroup.logGroupName,
            //   logType: NetFW.LogType.FLOW,
            // }],
            loggingS3Buckets: [
                {
                    bucketName: s3LoggingBucket.bucketName,
                    logType: NetFW.LogType.ALERT,
                    prefix: 'alerts',
                },
                {
                    bucketName: s3LoggingBucket.bucketName,
                    logType: NetFW.LogType.FLOW,
                    prefix: 'flow',
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
new TestStack(app, 'network-firewall-integ-stack');
// new IntegTest(app, 'AllBasicTest', {
//   testCases: [new TestStack(app, 'network-firewall-integ-stack')],
// });
app.synth();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50ZWcuZmlyZXdhbGwuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyJpbnRlZy5maXJld2FsbC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLDREQUE0RDtBQUM1RCwyQ0FBMkM7QUFDM0MseUNBQXlDO0FBQ3pDLHdDQUF3QztBQUN4QyxnQ0FBZ0M7QUFFaEMsTUFBTSxTQUFVLFNBQVEsR0FBRyxDQUFDLEtBQUs7SUFDL0IsWUFBWSxLQUFjLEVBQUUsRUFBVSxFQUFFLEtBQXNCO1FBQzVELEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBQ3hCLE1BQU0sR0FBRyxHQUFHLElBQUksR0FBRyxDQUFDLEdBQUcsQ0FBQyxJQUFJLEVBQUUsV0FBVyxFQUFFO1lBQ3pDLFdBQVcsRUFBRSxHQUFHLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUM7U0FDakQsQ0FBQyxDQUFDO1FBRUgsK0JBQStCO1FBQy9CLDRFQUE0RTtRQUU1RSxNQUFNLGVBQWUsR0FBRyxJQUFJLEVBQUUsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLHFCQUFxQixDQUFDLENBQUM7UUFFbkUsdUVBQXVFO1FBQ3ZFLGtDQUFrQztRQUNsQyxNQUFNO1FBRU4scUNBQXFDO1FBRXJDLE1BQU0sa0JBQWtCLEdBQUcsSUFBSSxLQUFLLENBQUMsa0JBQWtCLENBQUM7WUFDdEQsTUFBTSxFQUFFLEtBQUssQ0FBQyxzQkFBc0IsQ0FBQyxJQUFJO1lBQ3pDLGVBQWUsRUFBRSxZQUFZO1lBQzdCLFdBQVcsRUFBRSxXQUFXO1lBQ3hCLFFBQVEsRUFBRSxLQUFLO1lBQ2YsVUFBVSxFQUFFLEtBQUs7WUFDakIsTUFBTSxFQUFFLGNBQWM7WUFDdEIsU0FBUyxFQUFFLEtBQUssQ0FBQyx1QkFBdUIsQ0FBQyxPQUFPO1lBQ2hELFdBQVcsRUFBRTtnQkFDWDtvQkFDRSxPQUFPLEVBQUUsS0FBSztvQkFDZCxRQUFRLEVBQUUsQ0FBQyxNQUFNLENBQUM7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LE1BQU07QUFDTixHQUFHLENBQUMsS0FBSyxFQUFFLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvL2ltcG9ydCB7IEludGVnVGVzdCB9IGZyb20gJ2F3cy1jZGstbGliL2ludGVnLXRlc3RzLWFscGhhJztcbmltcG9ydCAqIGFzIGVjMiBmcm9tICdhd3MtY2RrLWxpYi9hd3MtZWMyJztcbmltcG9ydCAqIGFzIHMzIGZyb20gJ2F3cy1jZGstbGliL2F3cy1zMyc7XG5pbXBvcnQgKiBhcyBjZGsgZnJvbSAnYXdzLWNkay1saWIvY29yZSc7XG5pbXBvcnQgKiBhcyBOZXRGVyBmcm9tICcuLi9saWInO1xuXG5jbGFzcyBUZXN0U3RhY2sgZXh0ZW5kcyBjZGsuU3RhY2sge1xuICBjb25zdHJ1Y3RvcihzY29wZTogY2RrLkFwcCwgaWQ6IHN0cmluZywgcHJvcHM/OiBjZGsuU3RhY2tQcm9wcykge1xuICAgIHN1cGVyKHNjb3BlLCBpZCwgcHJvcHMpO1xuICAgIGNvbnN0IHZwYyA9IG5ldyBlYzIuVnBjKHRoaXMsICdNeVRlc3RWcGMnLCB7XG4gICAgICBpcEFkZHJlc3NlczogZWMyLklwQWRkcmVzc2VzLmNpZHIoJzEwLjAuMC4wLzE2JyksXG4gICAgfSk7XG5cbiAgICAvLyBTZXR0aW5nIHVwIGxvZ2dpbmcgbG9jYXRpb25zXG4gICAgLy8gY29uc3QgY2xvdWRXYXRjaExvZ0dyb3VwID0gbmV3IGxvZ3MuTG9nR3JvdXAodGhpcywgJ015RmlyZXdhbGxMb2dHcm91cCcpO1xuXG4gICAgY29uc3QgczNMb2dnaW5nQnVja2V0ID0gbmV3IHMzLkJ1Y2tldCh0aGlzLCAnTXlGaXJld2FsbExvZ0J1Y2tldCcpO1xuXG4gICAgLy8gY29uc3Qga2luZXNpc1N0cmVhbSA9IG5ldyBraW5lc2lzLlN0cmVhbSh0aGlzLCAnTXlGaXJld2FsbFN0cmVhbScsIHtcbiAgICAvLyAgIHN0cmVhbU5hbWU6ICdteS10ZXN0LXN0cmVhbScsXG4gICAgLy8gfSk7XG5cbiAgICAvLyBTZXR1cCBTdGF0ZWZ1bCA1VHVwbGUgcnVsZSAmIEdyb3VwXG5cbiAgICBjb25zdCBzdGF0ZWZ1bDVUdXBsZVJ1bGUgPSBuZXcgTmV0RlcuU3RhdGVmdWw1VHVwbGVSdWxlKHtcbiAgICAgIGFjdGlvbjogTmV0RlcuU3RhdGVmdWxTdGFuZGFyZEFjdGlvbi5EUk9QLFxuICAgICAgZGVzdGluYXRpb25Qb3J0OiAnJFdFQl9QT1JUUycsXG4gICAgICBkZXN0aW5hdGlvbjogJyRIT01FX05FVCcsXG4gICAgICBwcm90b2NvbDogJ1RDUCcsXG4gICAgICBzb3VyY2VQb3J0OiAnYW55JyxcbiAgICAgIHNvdXJjZTogJzEwLjEwLjAuMC8xNicsXG4gICAgICBkaXJlY3Rpb246IE5ldEZXLlN0YXRlZnVsNVR1cGxlRGlyZWN0aW9uLkZPUldBUkQsXG4gICAgICBydWxlT3B0aW9uczogW1xuICAgICAgICB7XG4gICAgICAgICAga2V5d29yZDogJ3NpZCcsXG4gICAgICAgICAgc2V0dGluZ3M6IFsnMTIzNCddLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIGNvbnN0IHN0YXRlZnVsNVR1cGxlUnVsZUdyb3VwID0gbmV3IE5ldEZXLlN0YXRlZnVsNVR1cGxlUnVsZUdyb3VwKHRoaXMsICdNeVN0YXRlZnVsNVR1cGxlUnVsZUdyb3VwJywge1xuICAgICAgY2FwYWNpdHk6IDEwMCxcbiAgICAgIHJ1bGVzOiBbc3RhdGVmdWw1VHVwbGVSdWxlXSxcbiAgICAgIHZhcmlhYmxlczoge1xuICAgICAgICBpcFNldHM6IHtcbiAgICAgICAgICBIT01FX05FVDogeyBkZWZpbml0aW9uOiBbJzEwLjAuMC4wLzE2JywgJzEwLjEwLjAuMC8xNiddIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHBvcnRTZXRzOiB7XG4gICAgICAgICAgV0VCX1BPUlRTOiB7IGRlZmluaXRpb246IFsnNDQzJywgJzgwJ10gfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBTZXR1cCBTdGF0ZWZ1bCBEb21haW4gbGlzdCBydWxlICYgR3JvdXBcblxuICAgIGNvbnN0IHN0YXRlZnVsRG9tYWluTGlzdFJ1bGUgPSBuZXcgTmV0RlcuU3RhdGVmdWxEb21haW5MaXN0UnVsZSh7XG4gICAgICB0eXBlOiBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RUeXBlLkRFTllMSVNULFxuICAgICAgdGFyZ2V0czogWycuZXhhbXBsZS5jb20nLCAnd3d3LmV4YW1wbGUub3JnJ10sXG4gICAgICB0YXJnZXRUeXBlczogW1xuICAgICAgICBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RUYXJnZXRUeXBlLlRMU19TTkksXG4gICAgICAgIE5ldEZXLlN0YXRlZnVsRG9tYWluTGlzdFRhcmdldFR5cGUuSFRUUF9IT1NULFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIGNvbnN0IHN0YXRlZnVsRG9tYWluTGlzdFJ1bGVHcm91cCA9IG5ldyBOZXRGVy5TdGF0ZWZ1bERvbWFpbkxpc3RSdWxlR3JvdXAodGhpcywgJ015U3RhdGVmdWxEb21haW5MaXN0UnVsZUdyb3VwJywge1xuICAgICAgY2FwYWNpdHk6IDEwMCxcbiAgICAgIHJ1bGU6IHN0YXRlZnVsRG9tYWluTGlzdFJ1bGUsXG4gICAgfSk7XG5cbiAgICAvLyBTZXR1cCBTdGF0ZWZ1bCBTdXJpY2F0YSBydWxlICYgR3JvdXBcblxuICAgIGNvbnN0IHN0YXRlZnVsU3VyaWNhdGFSdWxlR3JvdXAgPSBuZXcgTmV0RlcuU3RhdGVmdWxTdXJpY2F0YVJ1bGVHcm91cCh0aGlzLCAnTXlTdGF0ZWZ1bFN1cmljYXRhUnVsZUdyb3VwJywge1xuICAgICAgY2FwYWNpdHk6IDEwMCxcbiAgICAgIHJ1bGVzOiAnYWxlcnQgdGNwICRFWFRFUk5BTF9ORVQgYW55IC0+ICRIVFRQX1NFUlZFUlMgJEhUVFBfUE9SVFMgKG1zZzpcXFwiLmh0cGFzc3dkIGFjY2VzcyBhdHRlbXB0XFxcIjsgZmxvdzp0b19zZXJ2ZXIsZXN0YWJsaXNoZWQ7IGNvbnRlbnQ6XFxcIi5odHBhc3N3ZFxcXCI7IG5vY2FzZTsgc2lkOjIxMDUwMzsgcmV2OjE7KScsXG4gICAgICB2YXJpYWJsZXM6IHtcbiAgICAgICAgaXBTZXRzOiB7XG4gICAgICAgICAgSFRUUF9TRVJWRVJTOiB7IGRlZmluaXRpb246IFsnMTAuMC4wLjAvMTYnXSB9LFxuICAgICAgICB9LFxuICAgICAgICBwb3J0U2V0czoge1xuICAgICAgICAgIEhUVFBfUE9SVFM6IHsgZGVmaW5pdGlvbjogWyc4MCcsICc4MDgwJ10gfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBTZXR1cCBTdGF0ZWxlc3MgcnVsZSAmIGdyb3VwXG5cbiAgICBjb25zdCBzdGF0ZWxlc3NSdWxlID0gbmV3IE5ldEZXLlN0YXRlbGVzc1J1bGUoe1xuICAgICAgYWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgZGVzdGluYXRpb25Qb3J0czogW1xuICAgICAgICB7XG4gICAgICAgICAgZnJvbVBvcnQ6IDgwLFxuICAgICAgICAgIHRvUG9ydDogODAsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBmcm9tUG9ydDogNDQzLFxuICAgICAgICAgIHRvUG9ydDogNDQzLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICAgIGRlc3RpbmF0aW9uczogWycxMC4wLjAuMC8xNiddLFxuICAgICAgcHJvdG9jb2xzOiBbNl0sXG4gICAgICBzb3VyY2VQb3J0czogW3tcbiAgICAgICAgZnJvbVBvcnQ6IDAsXG4gICAgICAgIHRvUG9ydDogNjU1MzUsXG4gICAgICB9XSxcbiAgICAgIHNvdXJjZXM6IFsnMTAuMC4wLjAvMTYnLCAnMTAuMTAuMC4wLzE2J10sXG4gICAgfSk7XG5cbiAgICBjb25zdCBzdGF0ZWxlc3NSdWxlR3JvdXAgPSBuZXcgTmV0RlcuU3RhdGVsZXNzUnVsZUdyb3VwKHRoaXMsICdNeVN0YXRlbGVzc1J1bGVHcm91cCcsIHtcbiAgICAgIHJ1bGVHcm91cE5hbWU6ICdNeVN0YXRlbGVzc1J1bGVHcm91cCcsXG4gICAgICBydWxlczogW3sgcnVsZTogc3RhdGVsZXNzUnVsZSwgcHJpb3JpdHk6IDEwIH1dLFxuICAgIH0pO1xuXG4gICAgLy8gRmluYWxseSBzZXR1cCBQb2xpY3kgYW5kIGZpcmV3YWxsLlxuICAgIGNvbnN0IHBvbGljeSA9IG5ldyBOZXRGVy5GaXJld2FsbFBvbGljeSh0aGlzLCAnTXlOZXR3b3JrZmlyZXdhbGxQb2xpY3knLCB7XG4gICAgICBzdGF0ZWxlc3NEZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVsZXNzRnJhZ21lbnREZWZhdWx0QWN0aW9uczogW05ldEZXLlN0YXRlbGVzc1N0YW5kYXJkQWN0aW9uLkRST1BdLFxuICAgICAgc3RhdGVmdWxSdWxlR3JvdXBzOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBydWxlR3JvdXA6IHN0YXRlZnVsRG9tYWluTGlzdFJ1bGVHcm91cCxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHJ1bGVHcm91cDogc3RhdGVmdWw1VHVwbGVSdWxlR3JvdXAsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBydWxlR3JvdXA6IHN0YXRlZnVsU3VyaWNhdGFSdWxlR3JvdXAsXG4gICAgICAgIH0sXG4gICAgICBdLFxuICAgICAgc3RhdGVsZXNzUnVsZUdyb3VwczogW1xuICAgICAgICB7XG4gICAgICAgICAgcHJpb3JpdHk6IDEwLFxuICAgICAgICAgIHJ1bGVHcm91cDogc3RhdGVsZXNzUnVsZUdyb3VwLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIG5ldyBOZXRGVy5GaXJld2FsbCh0aGlzLCAnbmV0d29ya0ZpcmV3YWxsJywge1xuICAgICAgZmlyZXdhbGxOYW1lOiAnbXktbmV0d29yay1maXJld2FsbCcsXG4gICAgICB2cGM6IHZwYyxcbiAgICAgIHBvbGljeTogcG9saWN5LFxuICAgICAgLy8gbG9nZ2luZ0Nsb3VkV2F0Y2hMb2dHcm91cHM6IFt7XG4gICAgICAvLyAgIGxvZ0dyb3VwOiBjbG91ZFdhdGNoTG9nR3JvdXAubG9nR3JvdXBOYW1lLFxuICAgICAgLy8gICBsb2dUeXBlOiBOZXRGVy5Mb2dUeXBlLkZMT1csXG4gICAgICAvLyB9XSxcbiAgICAgIGxvZ2dpbmdTM0J1Y2tldHM6IFtcbiAgICAgICAge1xuICAgICAgICAgIGJ1Y2tldE5hbWU6IHMzTG9nZ2luZ0J1Y2tldC5idWNrZXROYW1lLFxuICAgICAgICAgIGxvZ1R5cGU6IE5ldEZXLkxvZ1R5cGUuQUxFUlQsXG4gICAgICAgICAgcHJlZml4OiAnYWxlcnRzJyxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIGJ1Y2tldE5hbWU6IHMzTG9nZ2luZ0J1Y2tldC5idWNrZXROYW1lLFxuICAgICAgICAgIGxvZ1R5cGU6IE5ldEZXLkxvZ1R5cGUuRkxPVyxcbiAgICAgICAgICBwcmVmaXg6ICdmbG93JyxcbiAgICAgICAgfSxcbiAgICAgIF0sXG4gICAgICAvLyBsb2dnaW5nS2luZXNpc0RhdGFTdHJlYW1zOiBbe1xuICAgICAgLy8gICBkZWxpdmVyeVN0cmVhbToga2luZXNpc1N0cmVhbS5zdHJlYW1OYW1lLFxuICAgICAgLy8gICBsb2dUeXBlOiBOZXRGVy5Mb2dUeXBlLkFMRVJULFxuICAgICAgLy8gfV0sXG4gICAgfSk7XG4gIH1cbn1cblxuY29uc3QgYXBwID0gbmV3IGNkay5BcHAoKTtcbm5ldyBUZXN0U3RhY2soYXBwLCAnbmV0d29yay1maXJld2FsbC1pbnRlZy1zdGFjaycpO1xuLy8gbmV3IEludGVnVGVzdChhcHAsICdBbGxCYXNpY1Rlc3QnLCB7XG4vLyAgIHRlc3RDYXNlczogW25ldyBUZXN0U3RhY2soYXBwLCAnbmV0d29yay1maXJld2FsbC1pbnRlZy1zdGFjaycpXSxcbi8vIH0pO1xuYXBwLnN5bnRoKCk7Il19