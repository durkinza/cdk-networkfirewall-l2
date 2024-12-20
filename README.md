<div align="center">
    <h1> AWS CDK Network Firewall L2 </h1>
This repo holds some experimental L2 constructs for the

[AWS-CDK](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_networkfirewall-readme.html)
<br/>

[![release](https://github.com/durkinza/cdk-networkfirewall-l2/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/durkinza/cdk-networkfirewall-l2/actions/workflows/release.yml)

[![View on Construct Hub](https://constructs.dev/badge?package=%40durkinza%2Fcdk-networkfirewall-l2)](https://constructs.dev/packages/@durkinza/cdk-networkfirewall-l2) 

</div>

---
## Description

AWS Network Firewall is a stateful, managed, network firewall and intrusion detection and prevention service.
These L2 Constructs can be used to create managed network firewalls with stateful and stateless rules and rule groups.

The goal of these constructs is to provide a way to decouple the creation of firewall rules from their rule groups and reduce the amount of boilerplate code required to define a network firewall.


### Quick Start Examples
For new environments an example that matches the default Security Group rules [can be found here.](docs/example-only-outbound.md)

If you're adding a firewall to an existing environment that does not have an expectation of normal traffic, try the  [non-obtrusive approach here](docs/example-non-obtrusive.md).  
This example passively monitors packets to build a baseline of "normal" traffic that can then be used as a reference to build appropriate firewall rules. 


### Defaults 

The ideal examples shown below provide only the parameters required to create a resource. 
Wherever possible, optional parameters are available to give the same level of customization as the L1 API.

To keep the constructs unopinionated, default actions are required for deployment of new resources.
It may be possible to reduce boilerplate code more if default actions were to be defined. 
Some examples of possible opinionated approaches:

An unobtrusive logging approach, to promote implementation of network firewalls in existing stacks. 
> When a parameter in an L2 construct is optional, where it would normally be required for an L1 construct, an unobtrusive and logging default option would be implied. This allows resources to be implemented in an existing stack with minimal obstruction to the existing operation of the stack. 
> After implementing a network firewall with logging defaults in a testing environment, a user can define a standard of "normal traffic" for their environment and implement firewall rules and default actions to restrict traffic.

A more obtrusive, but higher security approach could be:
> When a parameter in an L2 construct is optional, where it would normally be required for an L1 construct, a default drop rule would be implied. This ensures traffic that is not specifically allowed is blocked, a user would need to define rules to allow the traffic that is expected in their environment.

For new policies, it would also be possible to mirror the defaults set for security groups, where a default action of drop is set, with a single stateless rule being set to allow all outbound traffic. This approach would require generating an entire set of Policy, Stateless group, and stateless rule.

In any case a user can overwrite the default action(s) and create their own policies and rules as they see fit. 
Given the relatively small amount of code required to define the resources with default actions, I would opt to leave the code unopinionated for the first revision, as defaults can be specified in a later revision if needed.

### Firewalls
An ideal implementation would allow users to create firewall with minimal boiler plate.
```ts
const policy = NetFW.FirewallPolicy.fromFirewallPolicyName(stack, 'MyNetworkFirewallPolicy', 'MyFirewallPolicy');
new NetFW.Firewall(stack, 'MyNetworkFirewall', {
  vpc: vpc,
  policy: policy,
});
```
Where the firewall would be created in the provided vpc with the given firewall policy applied. 

In this example, `policy` is defined only to meet the requirement that a firewall must have a firewall policy attached. 
As explained in the Defaults section above, it may be possible to generate a default policy when one is not provided.

### Firewall Policies
Firewall policy definitions can be done by referencing an existing name/ARN as shown in the last example, or by generating a new policy.
Since a policy does not require rule groups to be attached, it will only need a few requirements to get started.
```ts
new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
  statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
  statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
});
```

Editing an existing Policy (e.x. adding a rule group to an existing policy that has been referenced via ARN) would be out of scope. 

When applying rule groups to a policy, a unique priority of must be provided for each group.
```ts
const statelessRuleGroupList:NetFW.StatelessRuleGroupList[] = [
  {
    priority: 10,
    ruleGroup: statelessRuleGroup1,
  },
];
const statefulRuleGroupList:NetFW.StatefulRuleGroupList[] = [
  {
    priority: 10,
    ruleGroup: statefulRuleGroup1,
  },
  {
    priority: 20,
    ruleGroup: statefulRuleGroup2,
  },
  {
    priority: 30,
    ruleGroup: statefulRuleGroup3,
  },
];
const policy = new NetFW.FirewallPolicy(stack, 'MyNetworkFirewallPolicy', {
  statelessDefaultActions: [NetFW.StatelessStandardAction.DROP],
  statelessFragmentDefaultActions: [NetFW.StatelessStandardAction.DROP],
  statelessRuleGroups: statelessRuleGroupList,
  statefulRuleGroups: statefulRuleGroupList,
});
```

### Stateless Rule Groups
Stateless firewall rule groups can be defined by referencing an existing name/ARN, or by generating a new group. 
New groups don't require any rules to be defined, so their implementation can be fairly quick.
```ts
new NetFW.StatelessRuleGroup(stack, 'MyStatelessRuleGroup');
```

The capacity requirements of a stateless rule group is fairly trivial to determine programmatically, but it can't be edited throughout the life time of the rule group. ([ref](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-group-managing.html#nwfw-rule-group-capacity))
The stateless rule group could programmatically determine the capacity required for the rules assigned to it when no capacity is provided. Using the exact capacity requirements for a rule group by default may cause the user issues later if they decide to add another rule to the group.

Editing an existing rule-group (e.x. adding a rule to an existing group referenced via ARN) would be out of scope. 

##### Stateless Rules
Stateless rules are not defined as a resource in AWS, they only exist in the context of the rule group they are defined in. 
To allow stateless rules to be decoupled from the rule group throughout the stack, they are defined as their own class, but reduce down to a L1 `RuleDefinitionProperty`
```ts
new NetFW.StatelessRule({
  actions: [NetFW.StatelessStandardAction.DROP]
});
```

Assigning stateless rules to a stateless rule-group requires a priority mapping, similar to the way a rule-group requires a priority map when assigned to a policy.
```ts
const statelessRule1 = new NetFW.StatelessRule({
  actions: [NetFW.StatelessStandardAction.DROP],
});
const statelessRule2 = new NetFW.StatelessRule({
  actions: [NetFW.StatelessStandardAction.DROP],
});
new NetFW.StatelessRuleGroup(stack, 'MyStatelessRuleGroup', {
  rules: [
    {
      rule: statelessRule1,
      priority: 10,
    },
    {
      rule: statelessRule2,
      priority: 20,
    },
  ],
});
```

### Stateful Rule Groups
Stateful firewall rules are split into 3 categories (5Tuple, Suricata, Domain List).
The console requires the category of rules to be defined when creating the rule group. 
However, from my understanding, the L1 constructs reduced all 3 down into Suricata rules. So a single stateful rule group could hold a mix of all 3 types of rules.

It appeared easier to merge the three types in a future revision than to split them apart if the requirements happened to change. 
I opted to match the AWS console, giving each rule group category has it's own class. Stateful rule groups are based on the same abstract class, to reduce duplicate code.

Stateful rule groups can be defined with no actionable rules within them, so the minimal implementation would be the same for all of them.
```ts
new NetFW.Stateful5TupleRuleGroup(stack, 'MyStateful5TupleRuleGroup', {
  // Assumes the following
  // rules: None
  // ruleOrder: NetFW.StatefulRuleOptions.DEFAULT_ACTION_ORDER,
  // capacity: 100
});
new NetFW.StatefulDomainListRuleGroup(stack, 'MyStatefulDomainListRuleGroup', {
  // Assumes the following
  // rule: None
  // ruleOrder: NetFW.StatefulRuleOptions.DEFAULT_ACTION_ORDER,
  // capacity: 100
});
new NetFW.StatefulSuricataRuleGroup(stack, 'MyStatefulSuricataRuleGroup', {
  // Assumes the following
  // rules: ""
  // ruleOrder: NetFW.StatefulRuleOptions.DEFAULT_ACTION_ORDER,
  // capacity: 100
});
```

##### Stateful 5 Tuple Rules
To define a stateful 5tuple rule, all parameters must be provided to the L1 construct. In most cases the ANY keyword is used to generalize the rule as much as possible by default. Allowing the user to narrow down the rule as needed. A default action must be specified to determine what the rule does when it matches the traffic.
```ts
new NetFW.Stateful5TupleRule({
  action: NetFW.StatefulStandardAction.DROP,
  // Assumes the following
  // destination: 'ANY',
  // destinationPort: 'ANY',
  // direction: 'ANY',
  // protocol: 'IP',
  // source: 'ANY',
  // sourcePort: 'ANY',
  // ruleOptions: None
});
```
When adding the stateful 5Tuple rule to a stateful5Tuple rule-group, no priority is required, the ruleOrder assigned to the rule-group will be used. 

```ts
const stateful5TupleRule1 = new NetFW.Stateful5TupleRule({
  action: NetFW.StatefulStandardAction.DROP,
});
const stateful5TupleRule2 = new NetFW.Stateful5TupleRule({
  action: NetFW.StatefulStandardAction.PASS,
});
new NetFW.Stateful5TupleRuleGroup(stack, 'MyStateful5TupleRuleGroup', {
  capacity: 100,
  rules: [stateful5TupleRule1, stateful5TupleRule2],
});
```

##### Domain List Rules
When defining a Domain List, only a single set of targets can be provided, as set by the L1 construct. 
All Domain List specific parameters are required for this rule.
```ts
  const statefulDomainListRule = new NetFW.StatefulDomainListRule({
    type: NetFW.StatefulDomainListType.ALLOWLIST,
    targets: ["example.com"],
    targetTypes: [StatefulDomainListTargetType.HTTP_HOST],
  });
```
##### Suricata Rules
Suricata rules are just strings, so they don't have a class type, they are defined directly into the suricata rule-group.
```ts
new NetFW.StatefulSuricataRuleGroup(stack, 'MyStatefulSuricataRuleGroup', {
  rules: 'drop tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"evil.com"; startswith; nocase; endswith; msg:"matching TLS denylisted FQDNs"; priority:1; flow:to_server, established; sid:1; rev:1;)
          drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"evil.com"; startswith; endswith; msg:"matching HTTP denylisted FQDNs"; priority:1; flow:to_server, established; sid:2; rev:1;)'
});
```

Suricata rule groups can also be imported from a file.  
```ts
const ruleGroup:NetFW.StatefulSuricataRuleGroup = NetFW.StatefulSuricataRuleGroup.fromFile(stack, 'MyStatefulSuricataRuleGroup', {
      path: './suricata.rules'
});
```
All other arguments for creating a Suricata Rule Group are also supported here with an exception of the `rules` property.  
The `rules` property will be filled in with the contents from the file path, anything supplied will be ignored.

### Firewall Logs

Logging can be done using 3 AWS services, Cloud Watch trails, S3 buckets, and Kinesis Data Firehose streams.

The logging locations are configured with a Logging type, either Flow or Alert logs.
In the case of Alert logs, it is up to the firewall policy to decide when a log should be generated.

Logs can be configured to be sent to multiple locations simultaneously.

```ts
new NetFW.Firewall(stack, 'MyNetworkFirewall', {
  vpc: vpc,
  policy: policy,
  loggingCloudWatchLogGroups: [
    {
      logGroup: logGroup.logGroupName,
      logType: NetFW.LogType.ALERT,
    },
  ],
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
  loggingKinesisDataStreams: [
    {
      deliveryStream: kinesisStream.streamName,
      logType: NetFW.LogType.ALERT,
    }
  ],
});
```