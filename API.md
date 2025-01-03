# API Reference <a name="API Reference" id="api-reference"></a>

## Constructs <a name="Constructs" id="Constructs"></a>

### Firewall <a name="Firewall" id="@durkinza/cdk-networkfirewall-l2.Firewall"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IFirewall">IFirewall</a>

Defines a Network Firewall in the Stack.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.Firewall.Initializer"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

new Firewall(scope: Construct, id: string, props: FirewallProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps">FirewallProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.Firewall.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps">FirewallProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.addLoggingConfigurations">addLoggingConfigurations</a></code> | Add a Logging Configuration to the Firewall. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.Firewall.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.Firewall.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.Firewall.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

##### `addLoggingConfigurations` <a name="addLoggingConfigurations" id="@durkinza/cdk-networkfirewall-l2.Firewall.addLoggingConfigurations"></a>

```typescript
public addLoggingConfigurations(configurationName: string, logLocations: ILogLocation[]): LoggingConfiguration
```

Add a Logging Configuration to the Firewall.

###### `configurationName`<sup>Required</sup> <a name="configurationName" id="@durkinza/cdk-networkfirewall-l2.Firewall.addLoggingConfigurations.parameter.configurationName"></a>

- *Type:* string

The Name of the Logging configuration type.

---

###### `logLocations`<sup>Required</sup> <a name="logLocations" id="@durkinza/cdk-networkfirewall-l2.Firewall.addLoggingConfigurations.parameter.logLocations"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]

An array of Log Locations.

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallArn">fromFirewallArn</a></code> | Reference an existing Network Firewall, defined outside of the CDK code, by arn. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallName">fromFirewallName</a></code> | Reference an existing Network Firewall, defined outside of the CDK code, by name. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.Firewall.isConstruct"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

Firewall.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.Firewall.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.Firewall.isOwnedResource"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

Firewall.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.Firewall.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.Firewall.isResource"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

Firewall.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.Firewall.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromFirewallArn` <a name="fromFirewallArn" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallArn"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

Firewall.fromFirewallArn(scope: Construct, id: string, firewallArn: string)
```

Reference an existing Network Firewall, defined outside of the CDK code, by arn.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallArn.parameter.id"></a>

- *Type:* string

---

###### `firewallArn`<sup>Required</sup> <a name="firewallArn" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallArn.parameter.firewallArn"></a>

- *Type:* string

---

##### `fromFirewallName` <a name="fromFirewallName" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallName"></a>

```typescript
import { Firewall } from '@durkinza/cdk-networkfirewall-l2'

Firewall.fromFirewallName(scope: Construct, id: string, firewallName: string)
```

Reference an existing Network Firewall, defined outside of the CDK code, by name.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallName.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallName.parameter.id"></a>

- *Type:* string

---

###### `firewallName`<sup>Required</sup> <a name="firewallName" id="@durkinza/cdk-networkfirewall-l2.Firewall.fromFirewallName.parameter.firewallName"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.endpointIds">endpointIds</a></code> | <code>string[]</code> | The unique IDs of the firewall endpoints for all of the subnets that you attached to the firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.firewallArn">firewallArn</a></code> | <code>string</code> | The Arn of the Firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.firewallId">firewallId</a></code> | <code>string</code> | The physical name of the Firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.policy">policy</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a></code> | The associated firewall Policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingCloudWatchLogGroups">loggingCloudWatchLogGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a>[]</code> | The Cloud Watch Log Groups to send logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingConfigurations">loggingConfigurations</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration">ILoggingConfiguration</a>[]</code> | The list of references to the generated logging configurations. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingKinesisDataStreams">loggingKinesisDataStreams</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a>[]</code> | The Kinesis Data Stream locations. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingS3Buckets">loggingS3Buckets</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a>[]</code> | The S3 Buckets to send logs to. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `endpointIds`<sup>Required</sup> <a name="endpointIds" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.endpointIds"></a>

```typescript
public readonly endpointIds: string[];
```

- *Type:* string[]

The unique IDs of the firewall endpoints for all of the subnets that you attached to the firewall.

The subnets are not listed in any particular order.

---

##### `firewallArn`<sup>Required</sup> <a name="firewallArn" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.firewallArn"></a>

```typescript
public readonly firewallArn: string;
```

- *Type:* string

The Arn of the Firewall.

---

##### `firewallId`<sup>Required</sup> <a name="firewallId" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.firewallId"></a>

```typescript
public readonly firewallId: string;
```

- *Type:* string

The physical name of the Firewall.

---

##### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.policy"></a>

```typescript
public readonly policy: IFirewallPolicy;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a>

The associated firewall Policy.

---

##### `loggingCloudWatchLogGroups`<sup>Required</sup> <a name="loggingCloudWatchLogGroups" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingCloudWatchLogGroups"></a>

```typescript
public readonly loggingCloudWatchLogGroups: CloudWatchLogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a>[]

The Cloud Watch Log Groups to send logs to.

---

##### `loggingConfigurations`<sup>Required</sup> <a name="loggingConfigurations" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingConfigurations"></a>

```typescript
public readonly loggingConfigurations: ILoggingConfiguration[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration">ILoggingConfiguration</a>[]

The list of references to the generated logging configurations.

---

##### `loggingKinesisDataStreams`<sup>Required</sup> <a name="loggingKinesisDataStreams" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingKinesisDataStreams"></a>

```typescript
public readonly loggingKinesisDataStreams: KinesisDataFirehoseLogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a>[]

The Kinesis Data Stream locations.

---

##### `loggingS3Buckets`<sup>Required</sup> <a name="loggingS3Buckets" id="@durkinza/cdk-networkfirewall-l2.Firewall.property.loggingS3Buckets"></a>

```typescript
public readonly loggingS3Buckets: S3LogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a>[]

The S3 Buckets to send logs to.

---


### FirewallPolicy <a name="FirewallPolicy" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a>

Defines a Firewall Policy in the stack.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

new FirewallPolicy(scope: Construct, id: string, props: FirewallPolicyProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps">FirewallPolicyProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps">FirewallPolicyProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatefulRuleGroup">addStatefulRuleGroup</a></code> | Add a stateful rule group to the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatelessRuleGroup">addStatelessRuleGroup</a></code> | Add a stateless rule group to the policy. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

##### `addStatefulRuleGroup` <a name="addStatefulRuleGroup" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatefulRuleGroup"></a>

```typescript
public addStatefulRuleGroup(ruleGroup: StatefulRuleGroupList): void
```

Add a stateful rule group to the policy.

###### `ruleGroup`<sup>Required</sup> <a name="ruleGroup" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatefulRuleGroup.parameter.ruleGroup"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList">StatefulRuleGroupList</a>

The stateful rule group to add to the policy.

---

##### `addStatelessRuleGroup` <a name="addStatelessRuleGroup" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatelessRuleGroup"></a>

```typescript
public addStatelessRuleGroup(ruleGroup: StatelessRuleGroupList): void
```

Add a stateless rule group to the policy.

###### `ruleGroup`<sup>Required</sup> <a name="ruleGroup" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.addStatelessRuleGroup.parameter.ruleGroup"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList">StatelessRuleGroupList</a>

The stateless rule group to add to the policy.

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyArn">fromFirewallPolicyArn</a></code> | Reference existing firewall policy by Arn. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyName">fromFirewallPolicyName</a></code> | Reference existing firewall policy name. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isConstruct"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

FirewallPolicy.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isOwnedResource"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

FirewallPolicy.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isResource"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

FirewallPolicy.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromFirewallPolicyArn` <a name="fromFirewallPolicyArn" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyArn"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

FirewallPolicy.fromFirewallPolicyArn(scope: Construct, id: string, firewallPolicyArn: string)
```

Reference existing firewall policy by Arn.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyArn.parameter.id"></a>

- *Type:* string

---

###### `firewallPolicyArn`<sup>Required</sup> <a name="firewallPolicyArn" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyArn.parameter.firewallPolicyArn"></a>

- *Type:* string

the ARN of the existing firewall policy.

---

##### `fromFirewallPolicyName` <a name="fromFirewallPolicyName" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyName"></a>

```typescript
import { FirewallPolicy } from '@durkinza/cdk-networkfirewall-l2'

FirewallPolicy.fromFirewallPolicyName(scope: Construct, id: string, firewallPolicyName: string)
```

Reference existing firewall policy name.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyName.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyName.parameter.id"></a>

- *Type:* string

---

###### `firewallPolicyName`<sup>Required</sup> <a name="firewallPolicyName" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.fromFirewallPolicyName.parameter.firewallPolicyName"></a>

- *Type:* string

The name of the existing firewall policy.

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.firewallPolicyArn">firewallPolicyArn</a></code> | <code>string</code> | The Arn of the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.firewallPolicyId">firewallPolicyId</a></code> | <code>string</code> | The physical name of the firewall policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statefulDefaultActions">statefulDefaultActions</a></code> | <code>string[]</code> | The Default actions for packets that don't match a stateful rule. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statefulRuleGroups">statefulRuleGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList">StatefulRuleGroupList</a>[]</code> | The stateful rule groups in this policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessDefaultActions">statelessDefaultActions</a></code> | <code>string[]</code> | The Default actions for packets that don't match a stateless rule. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessFragmentDefaultActions">statelessFragmentDefaultActions</a></code> | <code>string[]</code> | The Default actions for fragment packets that don't match a stateless rule. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessRuleGroups">statelessRuleGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList">StatelessRuleGroupList</a>[]</code> | The stateless rule groups in this policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.tags">tags</a></code> | <code>aws-cdk-lib.Tag[]</code> | Tags to be added to the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.tlsInspectionConfiguration">tlsInspectionConfiguration</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a></code> | The TLS Inspection Configuration. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `firewallPolicyArn`<sup>Required</sup> <a name="firewallPolicyArn" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.firewallPolicyArn"></a>

```typescript
public readonly firewallPolicyArn: string;
```

- *Type:* string

The Arn of the policy.

---

##### `firewallPolicyId`<sup>Required</sup> <a name="firewallPolicyId" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.firewallPolicyId"></a>

```typescript
public readonly firewallPolicyId: string;
```

- *Type:* string

The physical name of the firewall policy.

---

##### `statefulDefaultActions`<sup>Required</sup> <a name="statefulDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statefulDefaultActions"></a>

```typescript
public readonly statefulDefaultActions: string[];
```

- *Type:* string[]

The Default actions for packets that don't match a stateful rule.

---

##### `statefulRuleGroups`<sup>Required</sup> <a name="statefulRuleGroups" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statefulRuleGroups"></a>

```typescript
public readonly statefulRuleGroups: StatefulRuleGroupList[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList">StatefulRuleGroupList</a>[]

The stateful rule groups in this policy.

---

##### `statelessDefaultActions`<sup>Required</sup> <a name="statelessDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessDefaultActions"></a>

```typescript
public readonly statelessDefaultActions: string[];
```

- *Type:* string[]

The Default actions for packets that don't match a stateless rule.

---

##### `statelessFragmentDefaultActions`<sup>Required</sup> <a name="statelessFragmentDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessFragmentDefaultActions"></a>

```typescript
public readonly statelessFragmentDefaultActions: string[];
```

- *Type:* string[]

The Default actions for fragment packets that don't match a stateless rule.

---

##### `statelessRuleGroups`<sup>Required</sup> <a name="statelessRuleGroups" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.statelessRuleGroups"></a>

```typescript
public readonly statelessRuleGroups: StatelessRuleGroupList[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList">StatelessRuleGroupList</a>[]

The stateless rule groups in this policy.

---

##### `tags`<sup>Required</sup> <a name="tags" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.tags"></a>

```typescript
public readonly tags: Tag[];
```

- *Type:* aws-cdk-lib.Tag[]

Tags to be added to the policy.

---

##### `tlsInspectionConfiguration`<sup>Optional</sup> <a name="tlsInspectionConfiguration" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicy.property.tlsInspectionConfiguration"></a>

```typescript
public readonly tlsInspectionConfiguration: ITLSInspectionConfiguration;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a>

The TLS Inspection Configuration.

---


### LoggingConfiguration <a name="LoggingConfiguration" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration">ILoggingConfiguration</a>

Defines a Logging Configuration in the Stack.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer"></a>

```typescript
import { LoggingConfiguration } from '@durkinza/cdk-networkfirewall-l2'

new LoggingConfiguration(scope: Construct, id: string, props: LoggingConfigurationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps">LoggingConfigurationProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps">LoggingConfigurationProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.iLogLocationsToLogDestinationConfigProperty">iLogLocationsToLogDestinationConfigProperty</a></code> | Convert ILogLocation array to L1 LogDestinationConfigProperty array. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

##### `iLogLocationsToLogDestinationConfigProperty` <a name="iLogLocationsToLogDestinationConfigProperty" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.iLogLocationsToLogDestinationConfigProperty"></a>

```typescript
public iLogLocationsToLogDestinationConfigProperty(logLocations: ILogLocation[]): LogDestinationConfigProperty[]
```

Convert ILogLocation array to L1 LogDestinationConfigProperty array.

###### `logLocations`<sup>Required</sup> <a name="logLocations" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.iLogLocationsToLogDestinationConfigProperty.parameter.logLocations"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]

An array of assorted Log Locations.

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isResource">isResource</a></code> | Check whether the given construct is a Resource. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isConstruct"></a>

```typescript
import { LoggingConfiguration } from '@durkinza/cdk-networkfirewall-l2'

LoggingConfiguration.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isOwnedResource"></a>

```typescript
import { LoggingConfiguration } from '@durkinza/cdk-networkfirewall-l2'

LoggingConfiguration.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isResource"></a>

```typescript
import { LoggingConfiguration } from '@durkinza/cdk-networkfirewall-l2'

LoggingConfiguration.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.firewallRef">firewallRef</a></code> | <code>string</code> | The associated firewall Arn. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.firewallName">firewallName</a></code> | <code>string</code> | The associated firewall Name. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.loggingLocations">loggingLocations</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]</code> | Defines how AWS Network Firewall performs logging for a Firewall. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `firewallRef`<sup>Required</sup> <a name="firewallRef" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.firewallRef"></a>

```typescript
public readonly firewallRef: string;
```

- *Type:* string

The associated firewall Arn.

---

##### `firewallName`<sup>Optional</sup> <a name="firewallName" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.firewallName"></a>

```typescript
public readonly firewallName: string;
```

- *Type:* string

The associated firewall Name.

---

##### `loggingLocations`<sup>Required</sup> <a name="loggingLocations" id="@durkinza/cdk-networkfirewall-l2.LoggingConfiguration.property.loggingLocations"></a>

```typescript
public readonly loggingLocations: ILogLocation[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]

Defines how AWS Network Firewall performs logging for a Firewall.

---


### Stateful5TupleRuleGroup <a name="Stateful5TupleRuleGroup" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a>

A Stateful Rule group that holds 5Tuple Rules.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer"></a>

```typescript
import { Stateful5TupleRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

new Stateful5TupleRuleGroup(scope: Construct, id: string, props?: Stateful5TupleRuleGroupProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps">Stateful5TupleRuleGroupProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Optional</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps">Stateful5TupleRuleGroupProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.fromRuleGroupArn">fromRuleGroupArn</a></code> | Reference existing Rule Group. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isConstruct"></a>

```typescript
import { Stateful5TupleRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

Stateful5TupleRuleGroup.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isOwnedResource"></a>

```typescript
import { Stateful5TupleRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

Stateful5TupleRuleGroup.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isResource"></a>

```typescript
import { Stateful5TupleRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

Stateful5TupleRuleGroup.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromRuleGroupArn` <a name="fromRuleGroupArn" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.fromRuleGroupArn"></a>

```typescript
import { Stateful5TupleRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

Stateful5TupleRuleGroup.fromRuleGroupArn(scope: Construct, id: string, ruleGroupArn: string)
```

Reference existing Rule Group.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.fromRuleGroupArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.fromRuleGroupArn.parameter.id"></a>

- *Type:* string

---

###### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.fromRuleGroupArn.parameter.ruleGroupArn"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---


### StatefulDomainListRuleGroup <a name="StatefulDomainListRuleGroup" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a>

A Stateful Rule group that holds Domain List Rules.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer"></a>

```typescript
import { StatefulDomainListRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

new StatefulDomainListRuleGroup(scope: Construct, id: string, props?: StatefulDomainListRuleGroupProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps">StatefulDomainListRuleGroupProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Optional</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps">StatefulDomainListRuleGroupProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.fromRuleGroupArn">fromRuleGroupArn</a></code> | Reference existing Rule Group. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isConstruct"></a>

```typescript
import { StatefulDomainListRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulDomainListRuleGroup.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isOwnedResource"></a>

```typescript
import { StatefulDomainListRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulDomainListRuleGroup.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isResource"></a>

```typescript
import { StatefulDomainListRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulDomainListRuleGroup.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromRuleGroupArn` <a name="fromRuleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.fromRuleGroupArn"></a>

```typescript
import { StatefulDomainListRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulDomainListRuleGroup.fromRuleGroupArn(scope: Construct, id: string, ruleGroupArn: string)
```

Reference existing Rule Group.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.fromRuleGroupArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.fromRuleGroupArn.parameter.id"></a>

- *Type:* string

---

###### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.fromRuleGroupArn.parameter.ruleGroupArn"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---


### StatefulSuricataRuleGroup <a name="StatefulSuricataRuleGroup" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a>

A Stateful Rule group that holds Suricata Rules.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

new StatefulSuricataRuleGroup(scope: Construct, id: string, props?: StatefulSuricataRuleGroupProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps">StatefulSuricataRuleGroupProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Optional</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps">StatefulSuricataRuleGroupProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromFile">fromFile</a></code> | Reference Suricata rules from a file,. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromRuleGroupArn">fromRuleGroupArn</a></code> | Reference existing Rule Group. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isConstruct"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulSuricataRuleGroup.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isOwnedResource"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulSuricataRuleGroup.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isResource"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulSuricataRuleGroup.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromFile` <a name="fromFile" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromFile"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulSuricataRuleGroup.fromFile(scope: Construct, id: string, props: StatefulSuricataRuleGroupFromFileProps)
```

Reference Suricata rules from a file,.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromFile.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromFile.parameter.id"></a>

- *Type:* string

---

###### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromFile.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps">StatefulSuricataRuleGroupFromFileProps</a>

---

##### `fromRuleGroupArn` <a name="fromRuleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromRuleGroupArn"></a>

```typescript
import { StatefulSuricataRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatefulSuricataRuleGroup.fromRuleGroupArn(scope: Construct, id: string, ruleGroupArn: string)
```

Reference existing Rule Group.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromRuleGroupArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromRuleGroupArn.parameter.id"></a>

- *Type:* string

---

###### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.fromRuleGroupArn.parameter.ruleGroupArn"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---


### StatelessRuleGroup <a name="StatelessRuleGroup" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup">IStatelessRuleGroup</a>

A Stateless Rule group that holds Stateless Rules.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

new StatelessRuleGroup(scope: Construct, id: string, props?: StatelessRuleGroupProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps">StatelessRuleGroupProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Optional</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps">StatelessRuleGroupProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.calculateCapacity">calculateCapacity</a></code> | Calculates the expected capacity required for all applied stateful rules. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

##### `calculateCapacity` <a name="calculateCapacity" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.calculateCapacity"></a>

```typescript
public calculateCapacity(): number
```

Calculates the expected capacity required for all applied stateful rules.

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupArn">fromStatelessRuleGroupArn</a></code> | Reference existing Rule Group by Arn. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupName">fromStatelessRuleGroupName</a></code> | Reference existing Rule Group by Name. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isConstruct"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatelessRuleGroup.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isOwnedResource"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatelessRuleGroup.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isResource"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatelessRuleGroup.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromStatelessRuleGroupArn` <a name="fromStatelessRuleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupArn"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatelessRuleGroup.fromStatelessRuleGroupArn(scope: Construct, id: string, statelessRuleGroupArn: string)
```

Reference existing Rule Group by Arn.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupArn.parameter.id"></a>

- *Type:* string

---

###### `statelessRuleGroupArn`<sup>Required</sup> <a name="statelessRuleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupArn.parameter.statelessRuleGroupArn"></a>

- *Type:* string

---

##### `fromStatelessRuleGroupName` <a name="fromStatelessRuleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupName"></a>

```typescript
import { StatelessRuleGroup } from '@durkinza/cdk-networkfirewall-l2'

StatelessRuleGroup.fromStatelessRuleGroupName(scope: Construct, id: string, statelessRuleGroupName: string)
```

Reference existing Rule Group by Name.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupName.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupName.parameter.id"></a>

- *Type:* string

---

###### `statelessRuleGroupName`<sup>Required</sup> <a name="statelessRuleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.fromStatelessRuleGroupName.parameter.statelessRuleGroupName"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---


### TLSInspectionConfiguration <a name="TLSInspectionConfiguration" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a>

Defines a Network Firewall TLS Inspection Configuration in the Stack.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

new TLSInspectionConfiguration(scope: Construct, id: string, props: TLSInspectionConfigurationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.scope">scope</a></code> | <code>constructs.Construct</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.id">id</a></code> | <code>string</code> | *No description.* |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps">TLSInspectionConfigurationProps</a></code> | *No description.* |

---

##### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.scope"></a>

- *Type:* constructs.Construct

---

##### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.id"></a>

- *Type:* string

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps">TLSInspectionConfigurationProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.toString">toString</a></code> | Returns a string representation of this construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.applyRemovalPolicy">applyRemovalPolicy</a></code> | Apply the given removal policy to this resource. |

---

##### `toString` <a name="toString" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.toString"></a>

```typescript
public toString(): string
```

Returns a string representation of this construct.

##### `applyRemovalPolicy` <a name="applyRemovalPolicy" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.applyRemovalPolicy"></a>

```typescript
public applyRemovalPolicy(policy: RemovalPolicy): void
```

Apply the given removal policy to this resource.

The Removal Policy controls what happens to this resource when it stops
being managed by CloudFormation, either because you've removed it from the
CDK application or because you've made a change that requires the resource
to be replaced.

The resource can be deleted (`RemovalPolicy.DESTROY`), or left in your AWS
account for data recovery and cleanup later (`RemovalPolicy.RETAIN`).

###### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.applyRemovalPolicy.parameter.policy"></a>

- *Type:* aws-cdk-lib.RemovalPolicy

---

#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isConstruct">isConstruct</a></code> | Checks if `x` is a construct. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isOwnedResource">isOwnedResource</a></code> | Returns true if the construct was created by CDK, and false otherwise. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isResource">isResource</a></code> | Check whether the given construct is a Resource. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationArn">fromConfigurationArn</a></code> | Reference an existing TLS Inspection Configuration, defined outside of the CDK code, by arn. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationName">fromConfigurationName</a></code> | Reference an existing TLS Inspection Configuration, defined outside of the CDK code, by name. |

---

##### ~~`isConstruct`~~ <a name="isConstruct" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isConstruct"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

TLSInspectionConfiguration.isConstruct(x: any)
```

Checks if `x` is a construct.

###### `x`<sup>Required</sup> <a name="x" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isConstruct.parameter.x"></a>

- *Type:* any

Any object.

---

##### `isOwnedResource` <a name="isOwnedResource" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isOwnedResource"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

TLSInspectionConfiguration.isOwnedResource(construct: IConstruct)
```

Returns true if the construct was created by CDK, and false otherwise.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isOwnedResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `isResource` <a name="isResource" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isResource"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

TLSInspectionConfiguration.isResource(construct: IConstruct)
```

Check whether the given construct is a Resource.

###### `construct`<sup>Required</sup> <a name="construct" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.isResource.parameter.construct"></a>

- *Type:* constructs.IConstruct

---

##### `fromConfigurationArn` <a name="fromConfigurationArn" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationArn"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

TLSInspectionConfiguration.fromConfigurationArn(scope: Construct, id: string, configurationArn: string)
```

Reference an existing TLS Inspection Configuration, defined outside of the CDK code, by arn.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationArn.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationArn.parameter.id"></a>

- *Type:* string

---

###### `configurationArn`<sup>Required</sup> <a name="configurationArn" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationArn.parameter.configurationArn"></a>

- *Type:* string

---

##### `fromConfigurationName` <a name="fromConfigurationName" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationName"></a>

```typescript
import { TLSInspectionConfiguration } from '@durkinza/cdk-networkfirewall-l2'

TLSInspectionConfiguration.fromConfigurationName(scope: Construct, id: string, TLSInspectionConfigurationName: string)
```

Reference an existing TLS Inspection Configuration, defined outside of the CDK code, by name.

###### `scope`<sup>Required</sup> <a name="scope" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationName.parameter.scope"></a>

- *Type:* constructs.Construct

---

###### `id`<sup>Required</sup> <a name="id" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationName.parameter.id"></a>

- *Type:* string

---

###### `TLSInspectionConfigurationName`<sup>Required</sup> <a name="TLSInspectionConfigurationName" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.fromConfigurationName.parameter.TLSInspectionConfigurationName"></a>

- *Type:* string

---

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tlsInspectionConfigurationArn">tlsInspectionConfigurationArn</a></code> | <code>string</code> | The Arn of the TLS Inspection Configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tlsInspectionConfigurationId">tlsInspectionConfigurationId</a></code> | <code>string</code> | The physical name of the TLS Inspection Configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.description">description</a></code> | <code>string</code> | The Description of the TLS Inspection Configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tags">tags</a></code> | <code>aws-cdk-lib.Tag[]</code> | Tags to be added to the TLS Inspection Configuration. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `tlsInspectionConfigurationArn`<sup>Required</sup> <a name="tlsInspectionConfigurationArn" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tlsInspectionConfigurationArn"></a>

```typescript
public readonly tlsInspectionConfigurationArn: string;
```

- *Type:* string

The Arn of the TLS Inspection Configuration.

---

##### `tlsInspectionConfigurationId`<sup>Required</sup> <a name="tlsInspectionConfigurationId" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tlsInspectionConfigurationId"></a>

```typescript
public readonly tlsInspectionConfigurationId: string;
```

- *Type:* string

The physical name of the TLS Inspection Configuration.

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string

The Description of the TLS Inspection Configuration.

---

##### `tags`<sup>Optional</sup> <a name="tags" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration.property.tags"></a>

```typescript
public readonly tags: Tag[];
```

- *Type:* aws-cdk-lib.Tag[]

Tags to be added to the TLS Inspection Configuration.

---


## Structs <a name="Structs" id="Structs"></a>

### CloudWatchLogLocationProps <a name="CloudWatchLogLocationProps" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps"></a>

Defines a Cloud Watch Log Group Logging Option.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps.Initializer"></a>

```typescript
import { CloudWatchLogLocationProps } from '@durkinza/cdk-networkfirewall-l2'

const cloudWatchLogLocationProps: CloudWatchLogLocationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps.property.logGroup">logGroup</a></code> | <code>string</code> | The name of the CloudWatch Log Group to send logs to. |

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---

##### `logGroup`<sup>Required</sup> <a name="logGroup" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps.property.logGroup"></a>

```typescript
public readonly logGroup: string;
```

- *Type:* string

The name of the CloudWatch Log Group to send logs to.

---

### FirewallPolicyProps <a name="FirewallPolicyProps" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps"></a>

The Properties for defining a Firewall policy.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.Initializer"></a>

```typescript
import { FirewallPolicyProps } from '@durkinza/cdk-networkfirewall-l2'

const firewallPolicyProps: FirewallPolicyProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessDefaultActions">statelessDefaultActions</a></code> | <code>string[]</code> | The actions to take on a packet if it doesn't match any of the stateless rules in the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessFragmentDefaultActions">statelessFragmentDefaultActions</a></code> | <code>string[]</code> | The actions to take on a fragmented packet if it doesn't match any of the stateless rules in the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.description">description</a></code> | <code>string</code> | The description of the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.firewallPolicyName">firewallPolicyName</a></code> | <code>string</code> | The descriptive name of the firewall policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulDefaultActions">statefulDefaultActions</a></code> | <code>string[]</code> | The default actions to take on a packet that doesn't match any stateful rules. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulEngineOptions">statefulEngineOptions</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnFirewallPolicy.StatefulEngineOptionsProperty</code> | Additional options governing how Network Firewall handles stateful rules. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulRuleGroups">statefulRuleGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList">StatefulRuleGroupList</a>[]</code> | The stateful rule groups that are used in the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessCustomActions">statelessCustomActions</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnFirewallPolicy.CustomActionProperty[]</code> | The custom action definitions that are available for use in the firewall policy's statelessDefaultActions setting. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessRuleGroups">statelessRuleGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList">StatelessRuleGroupList</a>[]</code> | References to the stateless rule groups that are used in the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.tags">tags</a></code> | <code>aws-cdk-lib.Tag[]</code> | Tags to be added to the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.tlsInspectionConfiguration">tlsInspectionConfiguration</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a></code> | AWS Network Firewall uses a TLS inspection configuration to decrypt traffic. |

---

##### `statelessDefaultActions`<sup>Required</sup> <a name="statelessDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessDefaultActions"></a>

```typescript
public readonly statelessDefaultActions: string[];
```

- *Type:* string[]

The actions to take on a packet if it doesn't match any of the stateless rules in the policy.

---

##### `statelessFragmentDefaultActions`<sup>Required</sup> <a name="statelessFragmentDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessFragmentDefaultActions"></a>

```typescript
public readonly statelessFragmentDefaultActions: string[];
```

- *Type:* string[]

The actions to take on a fragmented packet if it doesn't match any of the stateless rules in the policy.

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

The description of the policy.

---

##### `firewallPolicyName`<sup>Optional</sup> <a name="firewallPolicyName" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.firewallPolicyName"></a>

```typescript
public readonly firewallPolicyName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the firewall policy.

You can't change the name of a firewall policy after you create it.

---

##### `statefulDefaultActions`<sup>Optional</sup> <a name="statefulDefaultActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulDefaultActions"></a>

```typescript
public readonly statefulDefaultActions: string[];
```

- *Type:* string[]
- *Default:* undefined

The default actions to take on a packet that doesn't match any stateful rules.

The stateful default action is optional, and is only valid when using the strict rule order

---

##### `statefulEngineOptions`<sup>Optional</sup> <a name="statefulEngineOptions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulEngineOptions"></a>

```typescript
public readonly statefulEngineOptions: StatefulEngineOptionsProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnFirewallPolicy.StatefulEngineOptionsProperty
- *Default:* undefined

Additional options governing how Network Firewall handles stateful rules.

The stateful rule groups that you use in your policy must have stateful rule options settings that are compatible with these settings

---

##### `statefulRuleGroups`<sup>Optional</sup> <a name="statefulRuleGroups" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statefulRuleGroups"></a>

```typescript
public readonly statefulRuleGroups: StatefulRuleGroupList[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList">StatefulRuleGroupList</a>[]
- *Default:* undefined

The stateful rule groups that are used in the policy.

---

##### `statelessCustomActions`<sup>Optional</sup> <a name="statelessCustomActions" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessCustomActions"></a>

```typescript
public readonly statelessCustomActions: CustomActionProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnFirewallPolicy.CustomActionProperty[]
- *Default:* undefined

The custom action definitions that are available for use in the firewall policy's statelessDefaultActions setting.

---

##### `statelessRuleGroups`<sup>Optional</sup> <a name="statelessRuleGroups" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.statelessRuleGroups"></a>

```typescript
public readonly statelessRuleGroups: StatelessRuleGroupList[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList">StatelessRuleGroupList</a>[]
- *Default:* undefined

References to the stateless rule groups that are used in the policy.

---

##### `tags`<sup>Optional</sup> <a name="tags" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.tags"></a>

```typescript
public readonly tags: Tag[];
```

- *Type:* aws-cdk-lib.Tag[]
- *Default:* No tags applied

Tags to be added to the policy.

---

##### `tlsInspectionConfiguration`<sup>Optional</sup> <a name="tlsInspectionConfiguration" id="@durkinza/cdk-networkfirewall-l2.FirewallPolicyProps.property.tlsInspectionConfiguration"></a>

```typescript
public readonly tlsInspectionConfiguration: ITLSInspectionConfiguration;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a>
- *Default:* No TLS Inspection performed.

AWS Network Firewall uses a TLS inspection configuration to decrypt traffic.

Network Firewall re-encrypts the traffic before sending it to its destination.

---

### FirewallProps <a name="FirewallProps" id="@durkinza/cdk-networkfirewall-l2.FirewallProps"></a>

The Properties for defining a Firewall Resource.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.Initializer"></a>

```typescript
import { FirewallProps } from '@durkinza/cdk-networkfirewall-l2'

const firewallProps: FirewallProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.policy">policy</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a></code> | Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.vpc">vpc</a></code> | <code>aws-cdk-lib.aws_ec2.IVpc</code> | The unique identifier of the VPC where the firewall is in use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.deleteProtection">deleteProtection</a></code> | <code>boolean</code> | A flag indicating whether it is possible to delete the firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.description">description</a></code> | <code>string</code> | The description of the Firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.firewallName">firewallName</a></code> | <code>string</code> | The descriptive name of the firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.firewallPolicyChangeProtection">firewallPolicyChangeProtection</a></code> | <code>boolean</code> | A setting indicating whether the firewall is protected against a change to the firewall policy association. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingCloudWatchLogGroups">loggingCloudWatchLogGroups</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a>[]</code> | A list of CloudWatch LogGroups to send logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingKinesisDataStreams">loggingKinesisDataStreams</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a>[]</code> | A list of Kinesis Data Firehose to send logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingS3Buckets">loggingS3Buckets</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a>[]</code> | A list of S3 Buckets to send logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.subnetChangeProtection">subnetChangeProtection</a></code> | <code>boolean</code> | A setting indicating whether the firewall is protected against changes to the subnet associations. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.subnetMappings">subnetMappings</a></code> | <code>aws-cdk-lib.aws_ec2.SubnetSelection</code> | The public subnets that Network Firewall is using for the firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.FirewallProps.property.tags">tags</a></code> | <code>aws-cdk-lib.Tag[]</code> | Tags to be added to the firewall. |

---

##### `policy`<sup>Required</sup> <a name="policy" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.policy"></a>

```typescript
public readonly policy: IFirewallPolicy;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a>

Each firewall requires one firewall policy association, and you can use the same firewall policy for multiple firewalls.

---

##### `vpc`<sup>Required</sup> <a name="vpc" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.vpc"></a>

```typescript
public readonly vpc: IVpc;
```

- *Type:* aws-cdk-lib.aws_ec2.IVpc

The unique identifier of the VPC where the firewall is in use.

You can't change the VPC of a firewall after you create the firewall.

---

##### `deleteProtection`<sup>Optional</sup> <a name="deleteProtection" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.deleteProtection"></a>

```typescript
public readonly deleteProtection: boolean;
```

- *Type:* boolean
- *Default:* true

A flag indicating whether it is possible to delete the firewall.

A setting of TRUE indicates that the firewall is protected against deletion

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

The description of the Firewall.

---

##### `firewallName`<sup>Optional</sup> <a name="firewallName" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.firewallName"></a>

```typescript
public readonly firewallName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the firewall.

You can't change the name of a firewall after you create it.

---

##### `firewallPolicyChangeProtection`<sup>Optional</sup> <a name="firewallPolicyChangeProtection" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.firewallPolicyChangeProtection"></a>

```typescript
public readonly firewallPolicyChangeProtection: boolean;
```

- *Type:* boolean
- *Default:* true

A setting indicating whether the firewall is protected against a change to the firewall policy association.

Use this setting to protect against accidentally modifying the firewall policy for a firewall that is in use.

---

##### `loggingCloudWatchLogGroups`<sup>Optional</sup> <a name="loggingCloudWatchLogGroups" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingCloudWatchLogGroups"></a>

```typescript
public readonly loggingCloudWatchLogGroups: CloudWatchLogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a>[]
- *Default:* Logs will not be sent to a cloudwatch group.

A list of CloudWatch LogGroups to send logs to.

---

##### `loggingKinesisDataStreams`<sup>Optional</sup> <a name="loggingKinesisDataStreams" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingKinesisDataStreams"></a>

```typescript
public readonly loggingKinesisDataStreams: KinesisDataFirehoseLogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a>[]
- *Default:* Logs will not be sent to a Kinesis DataFirehose.

A list of Kinesis Data Firehose to send logs to.

---

##### `loggingS3Buckets`<sup>Optional</sup> <a name="loggingS3Buckets" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.loggingS3Buckets"></a>

```typescript
public readonly loggingS3Buckets: S3LogLocationProps[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a>[]
- *Default:* Logs will not be sent to an S3 bucket.

A list of S3 Buckets to send logs to.

---

##### `subnetChangeProtection`<sup>Optional</sup> <a name="subnetChangeProtection" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.subnetChangeProtection"></a>

```typescript
public readonly subnetChangeProtection: boolean;
```

- *Type:* boolean
- *Default:* true

A setting indicating whether the firewall is protected against changes to the subnet associations.

Use this setting to protect against accidentally modifying the subnet associations for a firewall that is in use.

---

##### `subnetMappings`<sup>Optional</sup> <a name="subnetMappings" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.subnetMappings"></a>

```typescript
public readonly subnetMappings: SubnetSelection;
```

- *Type:* aws-cdk-lib.aws_ec2.SubnetSelection
- *Default:* All public subnets of the VPC

The public subnets that Network Firewall is using for the firewall.

Each subnet must belong to a different Availability Zone.

---

##### `tags`<sup>Optional</sup> <a name="tags" id="@durkinza/cdk-networkfirewall-l2.FirewallProps.property.tags"></a>

```typescript
public readonly tags: Tag[];
```

- *Type:* aws-cdk-lib.Tag[]
- *Default:* No tags applied

Tags to be added to the firewall.

---

### KinesisDataFirehoseLogLocationProps <a name="KinesisDataFirehoseLogLocationProps" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps"></a>

Defines a Kinesis Delivery Stream Logging Option.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps.Initializer"></a>

```typescript
import { KinesisDataFirehoseLogLocationProps } from '@durkinza/cdk-networkfirewall-l2'

const kinesisDataFirehoseLogLocationProps: KinesisDataFirehoseLogLocationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps.property.deliveryStream">deliveryStream</a></code> | <code>string</code> | The name of the Kinesis Data Firehose delivery stream to send logs to. |

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---

##### `deliveryStream`<sup>Required</sup> <a name="deliveryStream" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps.property.deliveryStream"></a>

```typescript
public readonly deliveryStream: string;
```

- *Type:* string

The name of the Kinesis Data Firehose delivery stream to send logs to.

---

### LoggingConfigurationProps <a name="LoggingConfigurationProps" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps"></a>

The Properties for defining a Logging Configuration.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.Initializer"></a>

```typescript
import { LoggingConfigurationProps } from '@durkinza/cdk-networkfirewall-l2'

const loggingConfigurationProps: LoggingConfigurationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.firewallRef">firewallRef</a></code> | <code>string</code> | The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.firewallName">firewallName</a></code> | <code>string</code> | The name of the firewall that the logging configuration is associated with. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.loggingConfigurationName">loggingConfigurationName</a></code> | <code>string</code> | The physical name of this logging configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.loggingLocations">loggingLocations</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]</code> | Defines how AWS Network Firewall performs logging for a Firewall. |

---

##### `firewallRef`<sup>Required</sup> <a name="firewallRef" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.firewallRef"></a>

```typescript
public readonly firewallRef: string;
```

- *Type:* string

The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with.

You can't change the firewall specification after you create the logging configuration.

---

##### `firewallName`<sup>Optional</sup> <a name="firewallName" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.firewallName"></a>

```typescript
public readonly firewallName: string;
```

- *Type:* string
- *Default:* No firewall name is logged.

The name of the firewall that the logging configuration is associated with.

You can't change the firewall specification after you create the logging configuration.

---

##### `loggingConfigurationName`<sup>Optional</sup> <a name="loggingConfigurationName" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.loggingConfigurationName"></a>

```typescript
public readonly loggingConfigurationName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The physical name of this logging configuration.

---

##### `loggingLocations`<sup>Optional</sup> <a name="loggingLocations" id="@durkinza/cdk-networkfirewall-l2.LoggingConfigurationProps.property.loggingLocations"></a>

```typescript
public readonly loggingLocations: ILogLocation[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>[]
- *Default:* No logging locations are configured, no logs will be sent.

Defines how AWS Network Firewall performs logging for a Firewall.

---

### LogLocationProps <a name="LogLocationProps" id="@durkinza/cdk-networkfirewall-l2.LogLocationProps"></a>

Base Log Location structure.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.LogLocationProps.Initializer"></a>

```typescript
import { LogLocationProps } from '@durkinza/cdk-networkfirewall-l2'

const logLocationProps: LogLocationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationProps.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.LogLocationProps.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---

### S3LogLocationProps <a name="S3LogLocationProps" id="@durkinza/cdk-networkfirewall-l2.S3LogLocationProps"></a>

Defines a S3 Bucket Logging Option.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.Initializer"></a>

```typescript
import { S3LogLocationProps } from '@durkinza/cdk-networkfirewall-l2'

const s3LogLocationProps: S3LogLocationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.bucketName">bucketName</a></code> | <code>string</code> | The name of the S3 bucket to send logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.prefix">prefix</a></code> | <code>string</code> | The location prefix to use. |

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---

##### `bucketName`<sup>Required</sup> <a name="bucketName" id="@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.bucketName"></a>

```typescript
public readonly bucketName: string;
```

- *Type:* string

The name of the S3 bucket to send logs to.

---

##### `prefix`<sup>Optional</sup> <a name="prefix" id="@durkinza/cdk-networkfirewall-l2.S3LogLocationProps.property.prefix"></a>

```typescript
public readonly prefix: string;
```

- *Type:* string
- *Default:* no prefix is used.

The location prefix to use.

---

### Stateful5TupleRuleGroupProps <a name="Stateful5TupleRuleGroupProps" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps"></a>

Properties for defining a Stateful 5 Tuple Rule Group.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.Initializer"></a>

```typescript
import { Stateful5TupleRuleGroupProps } from '@durkinza/cdk-networkfirewall-l2'

const stateful5TupleRuleGroupProps: Stateful5TupleRuleGroupProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.capacity">capacity</a></code> | <code>number</code> | The maximum operating resources that this rule group can use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.description">description</a></code> | <code>string</code> | Description of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.ruleGroupName">ruleGroupName</a></code> | <code>string</code> | The descriptive name of the stateful rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.ruleOrder">ruleOrder</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a></code> | Rule Order. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.rules">rules</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule">Stateful5TupleRule</a>[]</code> | The rule group rules. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.variables">variables</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty</code> | Settings that are available for use in the rules. |

---

##### `capacity`<sup>Optional</sup> <a name="capacity" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.capacity"></a>

```typescript
public readonly capacity: number;
```

- *Type:* number
- *Default:* 200

The maximum operating resources that this rule group can use.

Estimate a stateful rule group's capacity as the number of rules that you expect to have in it during its lifetime.
You can't change this setting after you create the rule group

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

Description of the rule group.

---

##### `ruleGroupName`<sup>Optional</sup> <a name="ruleGroupName" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.ruleGroupName"></a>

```typescript
public readonly ruleGroupName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the stateful rule group.

---

##### `ruleOrder`<sup>Optional</sup> <a name="ruleOrder" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.ruleOrder"></a>

```typescript
public readonly ruleOrder: StatefulRuleOptions;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a>
- *Default:* STRICT_ORDER

Rule Order.

---

##### `rules`<sup>Optional</sup> <a name="rules" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.rules"></a>

```typescript
public readonly rules: Stateful5TupleRule[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule">Stateful5TupleRule</a>[]
- *Default:* undefined

The rule group rules.

---

##### `variables`<sup>Optional</sup> <a name="variables" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroupProps.property.variables"></a>

```typescript
public readonly variables: RuleVariablesProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty
- *Default:* undefined

Settings that are available for use in the rules.

---

### Stateful5TupleRuleProps <a name="Stateful5TupleRuleProps" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps"></a>

Properties for defining a 5 Tuple rule.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.Initializer"></a>

```typescript
import { Stateful5TupleRuleProps } from '@durkinza/cdk-networkfirewall-l2'

const stateful5TupleRuleProps: Stateful5TupleRuleProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.action">action</a></code> | <code>string</code> | The action to perform when a rule is matched. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.destination">destination</a></code> | <code>string</code> | Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.destinationPort">destinationPort</a></code> | <code>string</code> | The destination port to inspect for. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.direction">direction</a></code> | <code>string</code> | The direction of traffic flow to inspect. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.protocol">protocol</a></code> | <code>string</code> | The protocol to inspect for. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.ruleOptions">ruleOptions</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleOptionProperty[]</code> | Additional settings for a stateful rule, provided as keywords and settings. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.source">source</a></code> | <code>string</code> | Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.sourcePort">sourcePort</a></code> | <code>string</code> | The source IP address or address range to inspect for, in CIDR notation. |

---

##### `action`<sup>Required</sup> <a name="action" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.action"></a>

```typescript
public readonly action: string;
```

- *Type:* string

The action to perform when a rule is matched.

---

##### `destination`<sup>Optional</sup> <a name="destination" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.destination"></a>

```typescript
public readonly destination: string;
```

- *Type:* string
- *Default:* = ANY

Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

---

##### `destinationPort`<sup>Optional</sup> <a name="destinationPort" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.destinationPort"></a>

```typescript
public readonly destinationPort: string;
```

- *Type:* string
- *Default:* ANY

The destination port to inspect for.

You can specify an individual port, for example 1994 and you can specify a port range, for example 1990:1994 .
To match with any port, specify ANY

---

##### `direction`<sup>Optional</sup> <a name="direction" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.direction"></a>

```typescript
public readonly direction: string;
```

- *Type:* string
- *Default:* ANY

The direction of traffic flow to inspect.

If set to ANY, the inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source.
If set to FORWARD , the inspection only matches traffic going from the source to the destination.

---

##### `protocol`<sup>Optional</sup> <a name="protocol" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.protocol"></a>

```typescript
public readonly protocol: string;
```

- *Type:* string
- *Default:* IP

The protocol to inspect for.

To specify all, you can use IP , because all traffic on AWS and on the internet is IP.

---

##### `ruleOptions`<sup>Optional</sup> <a name="ruleOptions" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.ruleOptions"></a>

```typescript
public readonly ruleOptions: RuleOptionProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleOptionProperty[]
- *Default:* undefined

Additional settings for a stateful rule, provided as keywords and settings.

---

##### `source`<sup>Optional</sup> <a name="source" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.source"></a>

```typescript
public readonly source: string;
```

- *Type:* string
- *Default:* = ANY

Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

---

##### `sourcePort`<sup>Optional</sup> <a name="sourcePort" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps.property.sourcePort"></a>

```typescript
public readonly sourcePort: string;
```

- *Type:* string
- *Default:* ANY

The source IP address or address range to inspect for, in CIDR notation.

To match with any address, specify ANY.

---

### StatefulDomainListRuleGroupProps <a name="StatefulDomainListRuleGroupProps" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps"></a>

Defines a Stateful Domain List Rule group in the stack.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.Initializer"></a>

```typescript
import { StatefulDomainListRuleGroupProps } from '@durkinza/cdk-networkfirewall-l2'

const statefulDomainListRuleGroupProps: StatefulDomainListRuleGroupProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.capacity">capacity</a></code> | <code>number</code> | The maximum operating resources that this rule group can use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.description">description</a></code> | <code>string</code> | Description of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.rule">rule</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule">StatefulDomainListRule</a></code> | The Domain List rule. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.ruleGroupName">ruleGroupName</a></code> | <code>string</code> | The descriptive name of the stateful rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.ruleOrder">ruleOrder</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a></code> | Rule Order. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.variables">variables</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty</code> | Settings that are available for use in the rules. |

---

##### `capacity`<sup>Optional</sup> <a name="capacity" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.capacity"></a>

```typescript
public readonly capacity: number;
```

- *Type:* number
- *Default:* 200

The maximum operating resources that this rule group can use.

Estimate a stateful rule group's capacity as the number of rules that you expect to have in it during its lifetime.
You can't change this setting after you create the rule group

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

Description of the rule group.

---

##### `rule`<sup>Optional</sup> <a name="rule" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.rule"></a>

```typescript
public readonly rule: StatefulDomainListRule;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule">StatefulDomainListRule</a>
- *Default:* undefined

The Domain List rule.

---

##### `ruleGroupName`<sup>Optional</sup> <a name="ruleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.ruleGroupName"></a>

```typescript
public readonly ruleGroupName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the stateful rule group.

---

##### `ruleOrder`<sup>Optional</sup> <a name="ruleOrder" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.ruleOrder"></a>

```typescript
public readonly ruleOrder: StatefulRuleOptions;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a>
- *Default:* STRICT_ORDER

Rule Order.

---

##### `variables`<sup>Optional</sup> <a name="variables" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroupProps.property.variables"></a>

```typescript
public readonly variables: RuleVariablesProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty
- *Default:* undefined

Settings that are available for use in the rules.

---

### StatefulDomainListRuleProps <a name="StatefulDomainListRuleProps" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps"></a>

The properties for defining a Stateful Domain List Rule.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.Initializer"></a>

```typescript
import { StatefulDomainListRuleProps } from '@durkinza/cdk-networkfirewall-l2'

const statefulDomainListRuleProps: StatefulDomainListRuleProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.targets">targets</a></code> | <code>string[]</code> | The domains that you want to inspect for in your traffic flows. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.targetTypes">targetTypes</a></code> | <code>string[]</code> | The types of targets to inspect for. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.type">type</a></code> | <code>string</code> | Whether you want to allow or deny access to the domains in your target list. |

---

##### `targets`<sup>Required</sup> <a name="targets" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.targets"></a>

```typescript
public readonly targets: string[];
```

- *Type:* string[]

The domains that you want to inspect for in your traffic flows.

---

##### `targetTypes`<sup>Required</sup> <a name="targetTypes" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.targetTypes"></a>

```typescript
public readonly targetTypes: string[];
```

- *Type:* string[]

The types of targets to inspect for.

---

##### `type`<sup>Required</sup> <a name="type" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps.property.type"></a>

```typescript
public readonly type: string;
```

- *Type:* string

Whether you want to allow or deny access to the domains in your target list.

---

### StatefulRuleBaseProps <a name="StatefulRuleBaseProps" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleBaseProps"></a>

The properties for defining a generic Stateful Rule.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleBaseProps.Initializer"></a>

```typescript
import { StatefulRuleBaseProps } from '@durkinza/cdk-networkfirewall-l2'

const statefulRuleBaseProps: StatefulRuleBaseProps = { ... }
```


### StatefulRuleGroupList <a name="StatefulRuleGroupList" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList"></a>

Maps a priority to a stateful rule group item.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList.Initializer"></a>

```typescript
import { StatefulRuleGroupList } from '@durkinza/cdk-networkfirewall-l2'

const statefulRuleGroupList: StatefulRuleGroupList = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList.property.ruleGroup">ruleGroup</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a></code> | The stateful rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList.property.priority">priority</a></code> | <code>number</code> | The priority of the rule group in the policy. |

---

##### `ruleGroup`<sup>Required</sup> <a name="ruleGroup" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList.property.ruleGroup"></a>

```typescript
public readonly ruleGroup: IStatefulRuleGroup;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a>

The stateful rule group.

---

##### `priority`<sup>Optional</sup> <a name="priority" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleGroupList.property.priority"></a>

```typescript
public readonly priority: number;
```

- *Type:* number
- *Default:* Priority is only used when Strict order is set.

The priority of the rule group in the policy.

---

### StatefulSuricataRuleGroupFromFileProps <a name="StatefulSuricataRuleGroupFromFileProps" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps"></a>

Properties for defining a Stateful Suricata Rule Group from a file.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.Initializer"></a>

```typescript
import { StatefulSuricataRuleGroupFromFileProps } from '@durkinza/cdk-networkfirewall-l2'

const statefulSuricataRuleGroupFromFileProps: StatefulSuricataRuleGroupFromFileProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.path">path</a></code> | <code>string</code> | The suricata rules file location. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.capacity">capacity</a></code> | <code>number</code> | The maximum operating resources that this rule group can use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.description">description</a></code> | <code>string</code> | Description of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.encoding">encoding</a></code> | <code>string</code> | The encoding to use for the file. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.ruleGroupName">ruleGroupName</a></code> | <code>string</code> | The descriptive name of the stateful rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.ruleOrder">ruleOrder</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a></code> | Rule Order. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.variables">variables</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty</code> | Settings that are available for use in the rules. |

---

##### `path`<sup>Required</sup> <a name="path" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.path"></a>

```typescript
public readonly path: string;
```

- *Type:* string

The suricata rules file location.

---

##### `capacity`<sup>Optional</sup> <a name="capacity" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.capacity"></a>

```typescript
public readonly capacity: number;
```

- *Type:* number
- *Default:* 200

The maximum operating resources that this rule group can use.

Estimate a stateful rule group's capacity as the number of rules that you expect to have in it during its lifetime.
You can't change this setting after you create the rule group

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

Description of the rule group.

---

##### `encoding`<sup>Optional</sup> <a name="encoding" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.encoding"></a>

```typescript
public readonly encoding: string;
```

- *Type:* string
- *Default:* uft-8

The encoding to use for the file.

---

##### `ruleGroupName`<sup>Optional</sup> <a name="ruleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.ruleGroupName"></a>

```typescript
public readonly ruleGroupName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the stateful rule group.

---

##### `ruleOrder`<sup>Optional</sup> <a name="ruleOrder" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.ruleOrder"></a>

```typescript
public readonly ruleOrder: StatefulRuleOptions;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a>
- *Default:* STRICT_ORDER

Rule Order.

---

##### `variables`<sup>Optional</sup> <a name="variables" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupFromFileProps.property.variables"></a>

```typescript
public readonly variables: RuleVariablesProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty
- *Default:* undefined

Settings that are available for use in the rules.

---

### StatefulSuricataRuleGroupProps <a name="StatefulSuricataRuleGroupProps" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps"></a>

Properties for defining a Stateful Suricata Rule Group.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.Initializer"></a>

```typescript
import { StatefulSuricataRuleGroupProps } from '@durkinza/cdk-networkfirewall-l2'

const statefulSuricataRuleGroupProps: StatefulSuricataRuleGroupProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.capacity">capacity</a></code> | <code>number</code> | The maximum operating resources that this rule group can use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.description">description</a></code> | <code>string</code> | Description of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.ruleGroupName">ruleGroupName</a></code> | <code>string</code> | The descriptive name of the stateful rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.ruleOrder">ruleOrder</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a></code> | Rule Order. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.rules">rules</a></code> | <code>string</code> | The suricata rules. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.variables">variables</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty</code> | Settings that are available for use in the rules. |

---

##### `capacity`<sup>Optional</sup> <a name="capacity" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.capacity"></a>

```typescript
public readonly capacity: number;
```

- *Type:* number
- *Default:* 200

The maximum operating resources that this rule group can use.

Estimate a stateful rule group's capacity as the number of rules that you expect to have in it during its lifetime.
You can't change this setting after you create the rule group

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

Description of the rule group.

---

##### `ruleGroupName`<sup>Optional</sup> <a name="ruleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.ruleGroupName"></a>

```typescript
public readonly ruleGroupName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the stateful rule group.

---

##### `ruleOrder`<sup>Optional</sup> <a name="ruleOrder" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.ruleOrder"></a>

```typescript
public readonly ruleOrder: StatefulRuleOptions;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions">StatefulRuleOptions</a>
- *Default:* STRICT_ORDER

Rule Order.

---

##### `rules`<sup>Optional</sup> <a name="rules" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.rules"></a>

```typescript
public readonly rules: string;
```

- *Type:* string
- *Default:* undefined

The suricata rules.

---

##### `variables`<sup>Optional</sup> <a name="variables" id="@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroupProps.property.variables"></a>

```typescript
public readonly variables: RuleVariablesProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty
- *Default:* undefined

Settings that are available for use in the rules.

---

### StatelessRuleGroupList <a name="StatelessRuleGroupList" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList"></a>

Maps a priority to a stateless rule group item.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList.Initializer"></a>

```typescript
import { StatelessRuleGroupList } from '@durkinza/cdk-networkfirewall-l2'

const statelessRuleGroupList: StatelessRuleGroupList = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList.property.priority">priority</a></code> | <code>number</code> | The priority of the rule group in the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList.property.ruleGroup">ruleGroup</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup">IStatelessRuleGroup</a></code> | The stateless rule. |

---

##### `priority`<sup>Required</sup> <a name="priority" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList.property.priority"></a>

```typescript
public readonly priority: number;
```

- *Type:* number

The priority of the rule group in the policy.

---

##### `ruleGroup`<sup>Required</sup> <a name="ruleGroup" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupList.property.ruleGroup"></a>

```typescript
public readonly ruleGroup: IStatelessRuleGroup;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup">IStatelessRuleGroup</a>

The stateless rule.

---

### StatelessRuleGroupProps <a name="StatelessRuleGroupProps" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps"></a>

The properties for defining a Stateless Rule Group.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.Initializer"></a>

```typescript
import { StatelessRuleGroupProps } from '@durkinza/cdk-networkfirewall-l2'

const statelessRuleGroupProps: StatelessRuleGroupProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.capacity">capacity</a></code> | <code>number</code> | The maximum operating resources that this rule group can use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.customActions">customActions</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.CustomActionProperty[]</code> | An optional Non-standard action to use. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.description">description</a></code> | <code>string</code> | Description of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.ruleGroupName">ruleGroupName</a></code> | <code>string</code> | The descriptive name of the stateless rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.rules">rules</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleList">StatelessRuleList</a>[]</code> | The rule group rules. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.variables">variables</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty</code> | Settings that are available for use in the rules. |

---

##### `capacity`<sup>Optional</sup> <a name="capacity" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.capacity"></a>

```typescript
public readonly capacity: number;
```

- *Type:* number
- *Default:* Capacity is Calculated from rule requirements.

The maximum operating resources that this rule group can use.

---

##### `customActions`<sup>Optional</sup> <a name="customActions" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.customActions"></a>

```typescript
public readonly customActions: CustomActionProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.CustomActionProperty[]
- *Default:* undefined

An optional Non-standard action to use.

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* undefined

Description of the rule group.

---

##### `ruleGroupName`<sup>Optional</sup> <a name="ruleGroupName" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.ruleGroupName"></a>

```typescript
public readonly ruleGroupName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the stateless rule group.

---

##### `rules`<sup>Optional</sup> <a name="rules" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.rules"></a>

```typescript
public readonly rules: StatelessRuleList[];
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleList">StatelessRuleList</a>[]
- *Default:* undefined

The rule group rules.

---

##### `variables`<sup>Optional</sup> <a name="variables" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleGroupProps.property.variables"></a>

```typescript
public readonly variables: RuleVariablesProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleVariablesProperty
- *Default:* undefined

Settings that are available for use in the rules.

---

### StatelessRuleList <a name="StatelessRuleList" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleList"></a>

Maps a priority to a stateless rule.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleList.Initializer"></a>

```typescript
import { StatelessRuleList } from '@durkinza/cdk-networkfirewall-l2'

const statelessRuleList: StatelessRuleList = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleList.property.priority">priority</a></code> | <code>number</code> | The priority of the rule in the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleList.property.rule">rule</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule">StatelessRule</a></code> | The stateless rule. |

---

##### `priority`<sup>Required</sup> <a name="priority" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleList.property.priority"></a>

```typescript
public readonly priority: number;
```

- *Type:* number

The priority of the rule in the rule group.

---

##### `rule`<sup>Required</sup> <a name="rule" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleList.property.rule"></a>

```typescript
public readonly rule: StatelessRule;
```

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule">StatelessRule</a>

The stateless rule.

---

### StatelessRuleProps <a name="StatelessRuleProps" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps"></a>

Properties for defining a stateless rule.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.Initializer"></a>

```typescript
import { StatelessRuleProps } from '@durkinza/cdk-networkfirewall-l2'

const statelessRuleProps: StatelessRuleProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.actions">actions</a></code> | <code>string[]</code> | Rule Actions. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.destinationPorts">destinationPorts</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.PortRangeProperty[]</code> | The destination port to inspect for. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.destinations">destinations</a></code> | <code>string[]</code> | Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.protocols">protocols</a></code> | <code>number[]</code> | The protocols to inspect for, specified using each protocol's assigned internet protocol number (IANA). |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.sourcePorts">sourcePorts</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.PortRangeProperty[]</code> | The source ports to inspect for. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.sources">sources</a></code> | <code>string[]</code> | Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.tcpFlags">tcpFlags</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.TCPFlagFieldProperty[]</code> | TCP flags and masks to inspect packets for. |

---

##### `actions`<sup>Required</sup> <a name="actions" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.actions"></a>

```typescript
public readonly actions: string[];
```

- *Type:* string[]

Rule Actions.

The actions to take on a packet that matches one of the stateless rule definition's match attributes.

---

##### `destinationPorts`<sup>Optional</sup> <a name="destinationPorts" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.destinationPorts"></a>

```typescript
public readonly destinationPorts: PortRangeProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.PortRangeProperty[]
- *Default:* ANY

The destination port to inspect for.

You can specify an individual port, for example 1994 and you can specify a port range, for example 1990:1994.
To match with any port, specify ANY.

---

##### `destinations`<sup>Optional</sup> <a name="destinations" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.destinations"></a>

```typescript
public readonly destinations: string[];
```

- *Type:* string[]
- *Default:* ANY

Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

---

##### `protocols`<sup>Optional</sup> <a name="protocols" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.protocols"></a>

```typescript
public readonly protocols: number[];
```

- *Type:* number[]
- *Default:* ANY

The protocols to inspect for, specified using each protocol's assigned internet protocol number (IANA).

---

##### `sourcePorts`<sup>Optional</sup> <a name="sourcePorts" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.sourcePorts"></a>

```typescript
public readonly sourcePorts: PortRangeProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.PortRangeProperty[]
- *Default:* ANY

The source ports to inspect for.

---

##### `sources`<sup>Optional</sup> <a name="sources" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.sources"></a>

```typescript
public readonly sources: string[];
```

- *Type:* string[]
- *Default:* ANY

Specify an array of IP address or a block of IP addresses in Classless Inter-Domain Routing (CIDR) notation.

---

##### `tcpFlags`<sup>Optional</sup> <a name="tcpFlags" id="@durkinza/cdk-networkfirewall-l2.StatelessRuleProps.property.tcpFlags"></a>

```typescript
public readonly tcpFlags: TCPFlagFieldProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.TCPFlagFieldProperty[]
- *Default:* undefined

TCP flags and masks to inspect packets for.

---

### TLSInspectionConfigurationProps <a name="TLSInspectionConfigurationProps" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps"></a>

The Properties for defining a Firewall TLS Inspection Configuration.

#### Initializer <a name="Initializer" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.Initializer"></a>

```typescript
import { TLSInspectionConfigurationProps } from '@durkinza/cdk-networkfirewall-l2'

const tLSInspectionConfigurationProps: TLSInspectionConfigurationProps = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.serverCertificateConfigurations">serverCertificateConfigurations</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnTLSInspectionConfiguration.ServerCertificateConfigurationProperty[]</code> | The TLS Server Certificate Configuration Property. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.configurationName">configurationName</a></code> | <code>string</code> | The descriptive name of the TLS inspection configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.description">description</a></code> | <code>string</code> | The Description of the TLS Inspection Configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.tags">tags</a></code> | <code>aws-cdk-lib.Tag[]</code> | Tags to be added to the configuration. |

---

##### `serverCertificateConfigurations`<sup>Required</sup> <a name="serverCertificateConfigurations" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.serverCertificateConfigurations"></a>

```typescript
public readonly serverCertificateConfigurations: ServerCertificateConfigurationProperty[];
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnTLSInspectionConfiguration.ServerCertificateConfigurationProperty[]

The TLS Server Certificate Configuration Property.

---

##### `configurationName`<sup>Optional</sup> <a name="configurationName" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.configurationName"></a>

```typescript
public readonly configurationName: string;
```

- *Type:* string
- *Default:* CloudFormation-generated name

The descriptive name of the TLS inspection configuration.

You can't change the name of a TLS inspection configuration after you create it.

---

##### `description`<sup>Optional</sup> <a name="description" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.description"></a>

```typescript
public readonly description: string;
```

- *Type:* string
- *Default:* No Description

The Description of the TLS Inspection Configuration.

---

##### `tags`<sup>Optional</sup> <a name="tags" id="@durkinza/cdk-networkfirewall-l2.TLSInspectionConfigurationProps.property.tags"></a>

```typescript
public readonly tags: Tag[];
```

- *Type:* aws-cdk-lib.Tag[]
- *Default:* No tags applied

Tags to be added to the configuration.

---

## Classes <a name="Classes" id="Classes"></a>

### CloudWatchLogLocation <a name="CloudWatchLogLocation" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation"></a>

Defines a Cloud Watch Log Group Logging Configuration.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.Initializer"></a>

```typescript
import { CloudWatchLogLocation } from '@durkinza/cdk-networkfirewall-l2'

new CloudWatchLogLocation(props: CloudWatchLogLocationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocationProps">CloudWatchLogLocationProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logDestination">logDestination</a></code> | <code>{[ key: string ]: string}</code> | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logDestinationType">logDestinationType</a></code> | <code>string</code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logDestination`<sup>Required</sup> <a name="logDestination" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logDestination"></a>

```typescript
public readonly logDestination: {[ key: string ]: string};
```

- *Type:* {[ key: string ]: string}

The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logDestinationType"></a>

```typescript
public readonly logDestinationType: string;
```

- *Type:* string

The type of storage destination to send these logs to.

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---


### KinesisDataFirehoseLogLocation <a name="KinesisDataFirehoseLogLocation" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation"></a>

Defines a Kinesis Delivery Stream Logging Configuration.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.Initializer"></a>

```typescript
import { KinesisDataFirehoseLogLocation } from '@durkinza/cdk-networkfirewall-l2'

new KinesisDataFirehoseLogLocation(props: KinesisDataFirehoseLogLocationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocationProps">KinesisDataFirehoseLogLocationProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logDestination">logDestination</a></code> | <code>{[ key: string ]: string}</code> | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logDestinationType">logDestinationType</a></code> | <code>string</code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logDestination`<sup>Required</sup> <a name="logDestination" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logDestination"></a>

```typescript
public readonly logDestination: {[ key: string ]: string};
```

- *Type:* {[ key: string ]: string}

The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logDestinationType"></a>

```typescript
public readonly logDestinationType: string;
```

- *Type:* string

The type of storage destination to send these logs to.

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---


### LogLocationBase <a name="LogLocationBase" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>

Base Log Location class.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.Initializer"></a>

```typescript
import { LogLocationBase } from '@durkinza/cdk-networkfirewall-l2'

new LogLocationBase(logDestinationType: LogDestinationType, props: LogLocationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase.Initializer.parameter.logDestinationType">logDestinationType</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.LogDestinationType">LogDestinationType</a></code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationProps">LogLocationProps</a></code> | *No description.* |

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.Initializer.parameter.logDestinationType"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.LogDestinationType">LogDestinationType</a>

The type of storage destination to send these logs to.

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.LogLocationProps">LogLocationProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logDestination">logDestination</a></code> | <code>{[ key: string ]: string}</code> | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logDestinationType">logDestinationType</a></code> | <code>string</code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logDestination`<sup>Required</sup> <a name="logDestination" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logDestination"></a>

```typescript
public readonly logDestination: {[ key: string ]: string};
```

- *Type:* {[ key: string ]: string}

The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logDestinationType"></a>

```typescript
public readonly logDestinationType: string;
```

- *Type:* string

The type of storage destination to send these logs to.

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.LogLocationBase.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---


### S3LogLocation <a name="S3LogLocation" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation"></a>

Defines a S3 Bucket Logging configuration.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation.Initializer"></a>

```typescript
import { S3LogLocation } from '@durkinza/cdk-networkfirewall-l2'

new S3LogLocation(props: S3LogLocationProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocation.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocationProps">S3LogLocationProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logDestination">logDestination</a></code> | <code>{[ key: string ]: string}</code> | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logDestinationType">logDestinationType</a></code> | <code>string</code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logDestination`<sup>Required</sup> <a name="logDestination" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logDestination"></a>

```typescript
public readonly logDestination: {[ key: string ]: string};
```

- *Type:* {[ key: string ]: string}

The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logDestinationType"></a>

```typescript
public readonly logDestinationType: string;
```

- *Type:* string

The type of storage destination to send these logs to.

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.S3LogLocation.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---


### Stateful5TupleRule <a name="Stateful5TupleRule" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule"></a>

Generates a Stateful Rule from a 5 Tuple.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule.Initializer"></a>

```typescript
import { Stateful5TupleRule } from '@durkinza/cdk-networkfirewall-l2'

new Stateful5TupleRule(props: Stateful5TupleRuleProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps">Stateful5TupleRuleProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleProps">Stateful5TupleRuleProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule.property.resource">resource</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.StatefulRuleProperty</code> | The L1 Stateful Rule Property. |

---

##### `resource`<sup>Required</sup> <a name="resource" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule.property.resource"></a>

```typescript
public readonly resource: StatefulRuleProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.StatefulRuleProperty

The L1 Stateful Rule Property.

---


### StatefulDomainListRule <a name="StatefulDomainListRule" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule"></a>

Generates a Stateful Rule from a Domain List.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule.Initializer"></a>

```typescript
import { StatefulDomainListRule } from '@durkinza/cdk-networkfirewall-l2'

new StatefulDomainListRule(props: StatefulDomainListRuleProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps">StatefulDomainListRuleProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleProps">StatefulDomainListRuleProps</a>

---



#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule.property.resource">resource</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RulesSourceListProperty</code> | The L1 Stateful Rule Property. |

---

##### `resource`<sup>Required</sup> <a name="resource" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule.property.resource"></a>

```typescript
public readonly resource: RulesSourceListProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RulesSourceListProperty

The L1 Stateful Rule Property.

---


### StatefulRuleBase <a name="StatefulRuleBase" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleBase"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRule">IStatefulRule</a>

The shared base class of stateful rules.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleBase.Initializer"></a>

```typescript
import { StatefulRuleBase } from '@durkinza/cdk-networkfirewall-l2'

new StatefulRuleBase()
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |

---





### StatelessRule <a name="StatelessRule" id="@durkinza/cdk-networkfirewall-l2.StatelessRule"></a>

- *Implements:* <a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRule">IStatelessRule</a>

Defines a Network Firewall Stateless Rule.

#### Initializers <a name="Initializers" id="@durkinza/cdk-networkfirewall-l2.StatelessRule.Initializer"></a>

```typescript
import { StatelessRule } from '@durkinza/cdk-networkfirewall-l2'

new StatelessRule(props: StatelessRuleProps)
```

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule.Initializer.parameter.props">props</a></code> | <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps">StatelessRuleProps</a></code> | *No description.* |

---

##### `props`<sup>Required</sup> <a name="props" id="@durkinza/cdk-networkfirewall-l2.StatelessRule.Initializer.parameter.props"></a>

- *Type:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleProps">StatelessRuleProps</a>

---

#### Methods <a name="Methods" id="Methods"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule.calculateCapacity">calculateCapacity</a></code> | Calculate Rule Capacity Requirements. |

---

##### `calculateCapacity` <a name="calculateCapacity" id="@durkinza/cdk-networkfirewall-l2.StatelessRule.calculateCapacity"></a>

```typescript
public calculateCapacity(): number
```

Calculate Rule Capacity Requirements.

https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-group-managing.html#nwfw-rule-group-capacity


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule.property.resource">resource</a></code> | <code>aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleDefinitionProperty</code> | The L1 Stateless Rule Property. |

---

##### `resource`<sup>Required</sup> <a name="resource" id="@durkinza/cdk-networkfirewall-l2.StatelessRule.property.resource"></a>

```typescript
public readonly resource: RuleDefinitionProperty;
```

- *Type:* aws-cdk-lib.aws_networkfirewall.CfnRuleGroup.RuleDefinitionProperty

The L1 Stateless Rule Property.

---


## Protocols <a name="Protocols" id="Protocols"></a>

### IFirewall <a name="IFirewall" id="@durkinza/cdk-networkfirewall-l2.IFirewall"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.Firewall">Firewall</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IFirewall">IFirewall</a>

Defines a Network Firewall in the stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewall.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewall.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewall.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewall.property.firewallArn">firewallArn</a></code> | <code>string</code> | The Arn of the Firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewall.property.firewallId">firewallId</a></code> | <code>string</code> | The physical name of the Firewall. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.IFirewall.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.IFirewall.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.IFirewall.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `firewallArn`<sup>Required</sup> <a name="firewallArn" id="@durkinza/cdk-networkfirewall-l2.IFirewall.property.firewallArn"></a>

```typescript
public readonly firewallArn: string;
```

- *Type:* string

The Arn of the Firewall.

---

##### `firewallId`<sup>Required</sup> <a name="firewallId" id="@durkinza/cdk-networkfirewall-l2.IFirewall.property.firewallId"></a>

```typescript
public readonly firewallId: string;
```

- *Type:* string

The physical name of the Firewall.

---

### IFirewallPolicy <a name="IFirewallPolicy" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.FirewallPolicy">FirewallPolicy</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy">IFirewallPolicy</a>

Defines a Network Firewall Policy in the stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.firewallPolicyArn">firewallPolicyArn</a></code> | <code>string</code> | The Arn of the policy. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.firewallPolicyId">firewallPolicyId</a></code> | <code>string</code> | The physical name of the firewall policy. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `firewallPolicyArn`<sup>Required</sup> <a name="firewallPolicyArn" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.firewallPolicyArn"></a>

```typescript
public readonly firewallPolicyArn: string;
```

- *Type:* string

The Arn of the policy.

---

##### `firewallPolicyId`<sup>Required</sup> <a name="firewallPolicyId" id="@durkinza/cdk-networkfirewall-l2.IFirewallPolicy.property.firewallPolicyId"></a>

```typescript
public readonly firewallPolicyId: string;
```

- *Type:* string

The physical name of the firewall policy.

---

### ILoggingConfiguration <a name="ILoggingConfiguration" id="@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.LoggingConfiguration">LoggingConfiguration</a>, <a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration">ILoggingConfiguration</a>

Defines a Network Firewall Logging Configuration in the stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.firewallRef">firewallRef</a></code> | <code>string</code> | The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `firewallRef`<sup>Required</sup> <a name="firewallRef" id="@durkinza/cdk-networkfirewall-l2.ILoggingConfiguration.property.firewallRef"></a>

```typescript
public readonly firewallRef: string;
```

- *Type:* string

The Amazon Resource Name (ARN) of the Firewall that the logging configuration is associated with.

You can't change the firewall specification after you create the logging configuration.

---

### ILogLocation <a name="ILogLocation" id="@durkinza/cdk-networkfirewall-l2.ILogLocation"></a>

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.CloudWatchLogLocation">CloudWatchLogLocation</a>, <a href="#@durkinza/cdk-networkfirewall-l2.KinesisDataFirehoseLogLocation">KinesisDataFirehoseLogLocation</a>, <a href="#@durkinza/cdk-networkfirewall-l2.LogLocationBase">LogLocationBase</a>, <a href="#@durkinza/cdk-networkfirewall-l2.S3LogLocation">S3LogLocation</a>, <a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation">ILogLocation</a>

Defines a Log Location in the Stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logDestination">logDestination</a></code> | <code>{[ key: string ]: string}</code> | The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logDestinationType">logDestinationType</a></code> | <code>string</code> | The type of storage destination to send these logs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logType">logType</a></code> | <code>string</code> | The type of log to send. |

---

##### `logDestination`<sup>Required</sup> <a name="logDestination" id="@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logDestination"></a>

```typescript
public readonly logDestination: {[ key: string ]: string};
```

- *Type:* {[ key: string ]: string}

The named location for the logs, provided in a key:value mapping that is specific to the chosen destination type.

---

##### `logDestinationType`<sup>Required</sup> <a name="logDestinationType" id="@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logDestinationType"></a>

```typescript
public readonly logDestinationType: string;
```

- *Type:* string

The type of storage destination to send these logs to.

---

##### `logType`<sup>Required</sup> <a name="logType" id="@durkinza/cdk-networkfirewall-l2.ILogLocation.property.logType"></a>

```typescript
public readonly logType: string;
```

- *Type:* string

The type of log to send.

---

### IStatefulRule <a name="IStatefulRule" id="@durkinza/cdk-networkfirewall-l2.IStatefulRule"></a>

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRule">Stateful5TupleRule</a>, <a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRule">StatefulDomainListRule</a>, <a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleBase">StatefulRuleBase</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRule">IStatefulRule</a>

The interface that represents the shared values of the StatefulRules.



### IStatefulRuleGroup <a name="IStatefulRuleGroup" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleRuleGroup">Stateful5TupleRuleGroup</a>, <a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListRuleGroup">StatefulDomainListRuleGroup</a>, <a href="#@durkinza/cdk-networkfirewall-l2.StatefulSuricataRuleGroup">StatefulSuricataRuleGroup</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup">IStatefulRuleGroup</a>

The Interface that represents a Stateful Rule Group.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.IStatefulRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---

### IStatelessRule <a name="IStatelessRule" id="@durkinza/cdk-networkfirewall-l2.IStatelessRule"></a>

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRule">StatelessRule</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRule">IStatelessRule</a>

The interface that represents the values of a StatelessRule.



### IStatelessRuleGroup <a name="IStatelessRuleGroup" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.StatelessRuleGroup">StatelessRuleGroup</a>, <a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup">IStatelessRuleGroup</a>

Defines a Stateless rule Group in the stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.ruleGroupArn">ruleGroupArn</a></code> | <code>string</code> | The Arn of the rule group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.ruleGroupId">ruleGroupId</a></code> | <code>string</code> | the physical name of the rule group. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `ruleGroupArn`<sup>Required</sup> <a name="ruleGroupArn" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.ruleGroupArn"></a>

```typescript
public readonly ruleGroupArn: string;
```

- *Type:* string

The Arn of the rule group.

---

##### `ruleGroupId`<sup>Required</sup> <a name="ruleGroupId" id="@durkinza/cdk-networkfirewall-l2.IStatelessRuleGroup.property.ruleGroupId"></a>

```typescript
public readonly ruleGroupId: string;
```

- *Type:* string

the physical name of the rule group.

---

### ITLSInspectionConfiguration <a name="ITLSInspectionConfiguration" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration"></a>

- *Extends:* aws-cdk-lib.IResource

- *Implemented By:* <a href="#@durkinza/cdk-networkfirewall-l2.TLSInspectionConfiguration">TLSInspectionConfiguration</a>, <a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration">ITLSInspectionConfiguration</a>

Defines a TLS Inspection Configuration Resource in the stack.


#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.node">node</a></code> | <code>constructs.Node</code> | The tree node. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.env">env</a></code> | <code>aws-cdk-lib.ResourceEnvironment</code> | The environment this resource belongs to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.stack">stack</a></code> | <code>aws-cdk-lib.Stack</code> | The stack in which this resource is defined. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.tlsInspectionConfigurationArn">tlsInspectionConfigurationArn</a></code> | <code>string</code> | The Arn of the TLS Inspection Configuration. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.tlsInspectionConfigurationId">tlsInspectionConfigurationId</a></code> | <code>string</code> | The name of the TLS Inspection Configuration. |

---

##### `node`<sup>Required</sup> <a name="node" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.node"></a>

```typescript
public readonly node: Node;
```

- *Type:* constructs.Node

The tree node.

---

##### `env`<sup>Required</sup> <a name="env" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.env"></a>

```typescript
public readonly env: ResourceEnvironment;
```

- *Type:* aws-cdk-lib.ResourceEnvironment

The environment this resource belongs to.

For resources that are created and managed by the CDK
(generally, those created by creating new class instances like Role, Bucket, etc.),
this is always the same as the environment of the stack they belong to;
however, for imported resources
(those obtained from static methods like fromRoleArn, fromBucketName, etc.),
that might be different than the stack they were imported into.

---

##### `stack`<sup>Required</sup> <a name="stack" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.stack"></a>

```typescript
public readonly stack: Stack;
```

- *Type:* aws-cdk-lib.Stack

The stack in which this resource is defined.

---

##### `tlsInspectionConfigurationArn`<sup>Required</sup> <a name="tlsInspectionConfigurationArn" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.tlsInspectionConfigurationArn"></a>

```typescript
public readonly tlsInspectionConfigurationArn: string;
```

- *Type:* string

The Arn of the TLS Inspection Configuration.

---

##### `tlsInspectionConfigurationId`<sup>Required</sup> <a name="tlsInspectionConfigurationId" id="@durkinza/cdk-networkfirewall-l2.ITLSInspectionConfiguration.property.tlsInspectionConfigurationId"></a>

```typescript
public readonly tlsInspectionConfigurationId: string;
```

- *Type:* string

The name of the TLS Inspection Configuration.

---

## Enums <a name="Enums" id="Enums"></a>

### LogDestinationType <a name="LogDestinationType" id="@durkinza/cdk-networkfirewall-l2.LogDestinationType"></a>

The type of storage destination to send these logs to.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogDestinationType.CLOUDWATCH">CLOUDWATCH</a></code> | Store logs to CloudWatch log group. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogDestinationType.KINESISDATAFIREHOSE">KINESISDATAFIREHOSE</a></code> | Store logs to a Kinesis Data Firehose delivery stream. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogDestinationType.S3">S3</a></code> | Store logs to an S3 bucket. |

---

##### `CLOUDWATCH` <a name="CLOUDWATCH" id="@durkinza/cdk-networkfirewall-l2.LogDestinationType.CLOUDWATCH"></a>

Store logs to CloudWatch log group.

---


##### `KINESISDATAFIREHOSE` <a name="KINESISDATAFIREHOSE" id="@durkinza/cdk-networkfirewall-l2.LogDestinationType.KINESISDATAFIREHOSE"></a>

Store logs to a Kinesis Data Firehose delivery stream.

---


##### `S3` <a name="S3" id="@durkinza/cdk-networkfirewall-l2.LogDestinationType.S3"></a>

Store logs to an S3 bucket.

---


### LogType <a name="LogType" id="@durkinza/cdk-networkfirewall-l2.LogType"></a>

The type of log to send.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogType.ALERT">ALERT</a></code> | Alert logs report traffic that matches a stateful rule with an action setting that sends an alert log message. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.LogType.FLOW">FLOW</a></code> | Flow logs are standard network traffic flow logs. |

---

##### `ALERT` <a name="ALERT" id="@durkinza/cdk-networkfirewall-l2.LogType.ALERT"></a>

Alert logs report traffic that matches a stateful rule with an action setting that sends an alert log message.

---


##### `FLOW` <a name="FLOW" id="@durkinza/cdk-networkfirewall-l2.LogType.FLOW"></a>

Flow logs are standard network traffic flow logs.

---


### Stateful5TupleDirection <a name="Stateful5TupleDirection" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleDirection"></a>

The direction of traffic flow to inspect.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleDirection.ANY">ANY</a></code> | Inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.Stateful5TupleDirection.FORWARD">FORWARD</a></code> | Inspection only matches traffic going from the source to the destination. |

---

##### `ANY` <a name="ANY" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleDirection.ANY"></a>

Inspection matches bidirectional traffic, both from the source to the destination and from the destination to the source.

---


##### `FORWARD` <a name="FORWARD" id="@durkinza/cdk-networkfirewall-l2.Stateful5TupleDirection.FORWARD"></a>

Inspection only matches traffic going from the source to the destination.

---


### StatefulDomainListTargetType <a name="StatefulDomainListTargetType" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListTargetType"></a>

The types of targets to inspect for.

You can inspect HTTP or HTTPS protocols, or both.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListTargetType.TLS_SNI">TLS_SNI</a></code> | Target HTTPS traffic For HTTPS traffic, Network Firewall uses the Server Name Indication (SNI) extension in the TLS handshake to determine the hostname, or domain name, that the client is trying to connect to. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListTargetType.HTTP_HOST">HTTP_HOST</a></code> | Target HTTP traffic. |

---

##### `TLS_SNI` <a name="TLS_SNI" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListTargetType.TLS_SNI"></a>

Target HTTPS traffic For HTTPS traffic, Network Firewall uses the Server Name Indication (SNI) extension in the TLS handshake to determine the hostname, or domain name, that the client is trying to connect to.

---


##### `HTTP_HOST` <a name="HTTP_HOST" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListTargetType.HTTP_HOST"></a>

Target HTTP traffic.

---


### StatefulDomainListType <a name="StatefulDomainListType" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListType"></a>

The type of domain list to generate.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListType.DENYLIST">DENYLIST</a></code> | Deny domain(s) through. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulDomainListType.ALLOWLIST">ALLOWLIST</a></code> | Allow domain(s) through. |

---

##### `DENYLIST` <a name="DENYLIST" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListType.DENYLIST"></a>

Deny domain(s) through.

---


##### `ALLOWLIST` <a name="ALLOWLIST" id="@durkinza/cdk-networkfirewall-l2.StatefulDomainListType.ALLOWLIST"></a>

Allow domain(s) through.

---


### StatefulRuleOptions <a name="StatefulRuleOptions" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions"></a>

Indicates how to manage the order of the rule evaluation for the rule group.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions.ACTION_ORDER">ACTION_ORDER</a></code> | Rules with a pass action are processed first, followed by drop, reject, and alert actions. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions.STRICT_ORDER">STRICT_ORDER</a></code> | With strict ordering, the rule groups are evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined. |

---

##### `ACTION_ORDER` <a name="ACTION_ORDER" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions.ACTION_ORDER"></a>

Rules with a pass action are processed first, followed by drop, reject, and alert actions.

This option was previously named Default Acton Order.

---


##### `STRICT_ORDER` <a name="STRICT_ORDER" id="@durkinza/cdk-networkfirewall-l2.StatefulRuleOptions.STRICT_ORDER"></a>

With strict ordering, the rule groups are evaluated by order of priority, starting from the lowest number, and the rules in each rule group are processed in the order in which they're defined.

Recommended Order

---


### StatefulStandardAction <a name="StatefulStandardAction" id="@durkinza/cdk-networkfirewall-l2.StatefulStandardAction"></a>

Defines what Network Firewall should do with the packets in a traffic flow when the flow matches the stateful rule criteria.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.PASS">PASS</a></code> | Permits the packets to go to the intended destination. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.DROP">DROP</a></code> | Blocks the packets from going to the intended destination and sends an alert log message, if alert logging is configured in the firewall. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.ALERT">ALERT</a></code> | Permits the packets to go to the intended destination and sends an alert log message, if alert logging is configured in the firewall. |

---

##### `PASS` <a name="PASS" id="@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.PASS"></a>

Permits the packets to go to the intended destination.

---


##### `DROP` <a name="DROP" id="@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.DROP"></a>

Blocks the packets from going to the intended destination and sends an alert log message, if alert logging is configured in the firewall.

---


##### `ALERT` <a name="ALERT" id="@durkinza/cdk-networkfirewall-l2.StatefulStandardAction.ALERT"></a>

Permits the packets to go to the intended destination and sends an alert log message, if alert logging is configured in the firewall.

---


### StatefulStrictAction <a name="StatefulStrictAction" id="@durkinza/cdk-networkfirewall-l2.StatefulStrictAction"></a>

The default actions to take on a packet that doesn't match any stateful rules.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.DROP_STRICT">DROP_STRICT</a></code> | Drops all packets. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.DROP_ESTABLISHED">DROP_ESTABLISHED</a></code> | Drops only the packets that are in established connections. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.ALERT_STRICT">ALERT_STRICT</a></code> | Logs an ALERT message on all packets. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.ALERT_ESTABLISHED">ALERT_ESTABLISHED</a></code> | Logs an ALERT message on only the packets that are in established connections. |

---

##### `DROP_STRICT` <a name="DROP_STRICT" id="@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.DROP_STRICT"></a>

Drops all packets.

---


##### `DROP_ESTABLISHED` <a name="DROP_ESTABLISHED" id="@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.DROP_ESTABLISHED"></a>

Drops only the packets that are in established connections.

This allows the layer 3 and 4 connection establishment packets that are needed for the upper-layer connections to be established, while dropping the packets for connections that are already established.
This allows application-layer pass rules to be written in a default-deny setup without the need to write additional rules to allow the lower-layer handshaking parts of the underlying protocols.

---


##### `ALERT_STRICT` <a name="ALERT_STRICT" id="@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.ALERT_STRICT"></a>

Logs an ALERT message on all packets.

This does not drop packets, but alerts you to what would be dropped if you were to choose Drop all.

---


##### `ALERT_ESTABLISHED` <a name="ALERT_ESTABLISHED" id="@durkinza/cdk-networkfirewall-l2.StatefulStrictAction.ALERT_ESTABLISHED"></a>

Logs an ALERT message on only the packets that are in established connections.

This does not drop packets, but alerts you to what would be dropped if you were to choose Drop established.

---


### StatelessStandardAction <a name="StatelessStandardAction" id="@durkinza/cdk-networkfirewall-l2.StatelessStandardAction"></a>

The actions to take on a packet that matches one of the stateless rule definition's match attributes.

#### Members <a name="Members" id="Members"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.FORWARD">FORWARD</a></code> | Discontinues stateless inspection of the packet and forwards it to the stateful rule engine for inspection. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.PASS">PASS</a></code> | Discontinues all inspection of the packet and permits it to go to its intended destination. |
| <code><a href="#@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.DROP">DROP</a></code> | Discontinues all inspection of the packet and blocks it from going to its intended destination. |

---

##### `FORWARD` <a name="FORWARD" id="@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.FORWARD"></a>

Discontinues stateless inspection of the packet and forwards it to the stateful rule engine for inspection.

---


##### `PASS` <a name="PASS" id="@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.PASS"></a>

Discontinues all inspection of the packet and permits it to go to its intended destination.

---


##### `DROP` <a name="DROP" id="@durkinza/cdk-networkfirewall-l2.StatelessStandardAction.DROP"></a>

Discontinues all inspection of the packet and blocks it from going to its intended destination.

---

