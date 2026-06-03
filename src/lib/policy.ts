import {
  CfnFirewallPolicy,
  CfnFirewallPolicyProps,
} from "aws-cdk-lib/aws-networkfirewall";
import * as core from "aws-cdk-lib/core";
import { Construct } from "constructs";
import { StatelessStandardAction, StatefulStrictAction } from "./actions";
import { IStatefulRuleGroup, IStatelessRuleGroup } from "./rule-group";
import { ITLSInspectionConfiguration } from "./tls-inspection";

/**
 * Configuration settings for the handling of the stateful rule groups in a firewall policy.
 * @see https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-networkfirewall-firewallpolicy-statefulengineoptions.html
 */
export enum StatefulEngineOptionsRuleOrder {
  /**
   * Rules with a pass action are processed first, followed by drop, reject, and alert actions.
   */
  ACTION_ORDER = "DEFAULT_ACTION_ORDER",

  /**
   * Rule groups are evaluated by order of priority, starting from the lowest number,
   * and the rules in each rule group are processed in the order in which they're defined.
   * Recommended Order.
   */
  STRICT_ORDER = "STRICT_ORDER",
}

/**
 * Configures how Network Firewall processes traffic when a network connection breaks midstream. Network connections can break due to disruptions in external networks or within the firewall itself.
 *
 * @see https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-networkfirewall-firewallpolicy-statefulengineoptions.html
 */
export enum StreamExceptionPolicy {
  /**
   * Network Firewall fails closed and drops all subsequent traffic going to the firewall. This is the default behavior.
   */
  DROP = "DROP",

  /**
   * Network Firewall continues to apply rules to the subsequent traffic without context from traffic before the break.
   * This impacts the behavior of rules that depend on this context.
   * For example, if you have a stateful rule to drop http traffic, Network Firewall won't match the traffic for this rule because the service won't have the context from session initialization defining the application layer protocol as HTTP. However, this behavior is rule dependent—a TCP-layer rule using a flow:stateless rule would still match, as would the aws:drop_strict default action.
   */
  CONTINUE = "CONTINUE",

  /**
   * Network Firewall fails closed and drops all subsequent traffic going to the firewall. Network Firewall also sends a TCP reject packet back to your client so that the client can immediately establish a new session. Network Firewall will have context about the new session and will apply rules to the subsequent traffic.
   */
  REJECT = "REJECT",
}

/**
 *  Maps a priority to a stateful rule group item
 */
export interface StatefulRuleGroupList {
  /**
   * The priority of the rule group in the policy
   * @default - Priority is only used when Strict order is set.
   */
  readonly priority?: number;

  /**
   * The stateful rule group
   */
  readonly ruleGroup: IStatefulRuleGroup;

  /**
   * Whether to enable deep threat inspection for this rule group.
   * When enabled, AWS Network Firewall analyzes network traffic processed by the rule group to improve threat detection.
   * @default - undefined
   */
  readonly deepThreatInspection?: boolean;

  /**
   * The action that allows the policy owner to override the behavior of the rule group within a policy.
   * @default - undefined
   */
  readonly override?: CfnFirewallPolicy.StatefulRuleGroupOverrideProperty;
}

/**
 * Maps a priority to a stateless rule group item
 */
export interface StatelessRuleGroupList {
  /**
   * The priority of the rule group in the policy
   */
  readonly priority: number;

  /**
   * The stateless rule
   */
  readonly ruleGroup: IStatelessRuleGroup;
}

/**
 * Defines a Network Firewall Policy in the stack
 */
export interface IFirewallPolicy extends core.IResource {
  /**
   * The Arn of the policy.
   * @attribute
   */
  readonly firewallPolicyArn: string;

  /**
   * The physical name of the firewall policy.
   * @attribute
   */
  readonly firewallPolicyId: string;
}

/**
 *
 */
abstract class FirewallPolicyBase
  extends core.Resource
  implements IFirewallPolicy
{
  /**
   * The Arn of the policy.
   * @attribute
   */
  public abstract readonly firewallPolicyArn: string;

  /**
   * The physical name of the firewall policy.
   * @attribute
   */
  public abstract readonly firewallPolicyId: string;
}

/**
 * The Properties for defining a Firewall policy
 */
export interface FirewallPolicyProps {
  /**
   * The descriptive name of the firewall policy.
   * You can't change the name of a firewall policy after you create it.
   * @default - CloudFormation-generated name
   */
  readonly firewallPolicyName?: string;

  /**
   * Configures the amount of time that can pass without any traffic sent through the firewall before the firewall determines that the connection is idle.
   * @default - undefined
   */
  readonly flowTimeouts?: CfnFirewallPolicy.FlowTimeoutsProperty;

  /**
   * How Network Firewall handles stateful rules.
   * The stateful rule groups that you use in your policy must match the policy's rule order.
   * @default - Matches the rule order of the first stateful rule group added to the policy, or STRICT_ORDER if no stateful rule groups are added.
   */
  readonly ruleOrder?: StatefulEngineOptionsRuleOrder | string;

  /**
   * The actions to take on a packet if it doesn't match any of the stateless rules in the policy.
   */
  readonly statelessDefaultActions: (StatelessStandardAction | string)[];

  /**
   * The actions to take on a fragmented packet if it doesn't match any of the stateless rules in the policy.
   */
  readonly statelessFragmentDefaultActions: (
    | StatelessStandardAction
    | string
  )[];

  /**
   * The default actions to take on a packet that doesn't match any stateful rules.
   * The stateful default action is optional, and is only valid when using the strict rule order
   * @default - undefined
   */
  readonly statefulDefaultActions?: (StatefulStrictAction | string)[];

  /**
   * The stateful rule groups that are used in the policy.
   * @default - undefined
   */
  readonly statefulRuleGroups?: StatefulRuleGroupList[];

  /**
   * A L1 construct can be passed in for the Engine Options
   * Overrides other stateful engine options properties if this is set.
   * @default - undefined
   */
  readonly statefulEngineOptions?: CfnFirewallPolicy.StatefulEngineOptionsProperty;

  /**
   * The custom action definitions that are available for use in the firewall policy's statelessDefaultActions setting.
   * @default - undefined
   */
  readonly statelessCustomActions?: CfnFirewallPolicy.CustomActionProperty[];

  /**
   * References to the stateless rule groups that are used in the policy.
   * @default - undefined
   */
  readonly statelessRuleGroups?: StatelessRuleGroupList[];

  /**
   * Configures how Network Firewall processes traffic when a network connection breaks midstream. Network connections can break due to disruptions in external networks or within the firewall itself.
   * @default - undefined
   */
  readonly streamExceptionPolicy?: StreamExceptionPolicy;

  /**
   * AWS Network Firewall uses a TLS inspection configuration to decrypt traffic.
   * Network Firewall re-encrypts the traffic before sending it to its destination.
   *
   * @default - No TLS Inspection performed.
   */
  readonly tlsInspectionConfiguration?: ITLSInspectionConfiguration;

  /**
   * When true, prevents TCP and TLS packets from reaching destination servers until
   * TLS Inspection has evaluated Server Name Indication (SNI) rules.
   * Requires an associated TLS Inspection configuration.
   * @default - undefined
   */
  readonly enableTlsSessionHolding?: boolean;

  /**
   * Contains variables that you can use to override default Suricata settings in your firewall policy.
   * @default - undefined
   */
  readonly policyVariables?: CfnFirewallPolicy.PolicyVariablesProperty;

  /**
   * The description of the policy.
   * @default - undefined
   */
  readonly description?: string;

  /**
   * Tags to be added to the policy.
   * @default - No tags applied
   */
  readonly tags?: core.Tag[];
}

/**
 * Defines a Firewall Policy in the stack
 * @resource AWS::NetworkFirewall::FirewallPolicy
 */
export class FirewallPolicy extends FirewallPolicyBase {
  /**
   * Reference existing firewall policy name
   * @param scope
   * @param id
   * @param firewallPolicyName The name of the existing firewall policy
   */
  public static fromFirewallPolicyName(
    scope: Construct,
    id: string,
    firewallPolicyName: string,
  ): IFirewallPolicy {
    /**
     * An ADHOC class for an imported firewall policy.
     */
    class Import extends FirewallPolicyBase {
      public readonly firewallPolicyId = firewallPolicyName;
      public readonly firewallPolicyArn = core.Stack.of(scope).formatArn({
        service: "network-firewall",
        resource: "firewall-policy",
        resourceName: firewallPolicyName,
      });
    }
    return new Import(scope, id);
  }

  /**
   * Reference existing firewall policy by Arn
   * @param scope
   * @param id
   * @param firewallPolicyArn the ARN of the existing firewall policy
   */
  public static fromFirewallPolicyArn(
    scope: Construct,
    id: string,
    firewallPolicyArn: string,
  ): IFirewallPolicy {
    /**
     * An ADHOC class for an imported firewall policy.
     */
    class Import extends FirewallPolicyBase {
      public readonly firewallPolicyId = core.Fn.select(
        1,
        core.Fn.split("/", firewallPolicyArn),
      );
      public readonly firewallPolicyArn = firewallPolicyArn;
    }
    return new Import(scope, id);
  }

  public readonly firewallPolicyArn: string;
  public readonly firewallPolicyId: string;

  /**
   * The Default actions for packets that don't match a stateless rule
   */
  public readonly statelessDefaultActions: string[] = [];

  /**
   * The Default actions for fragment packets that don't match a stateless rule
   */
  public readonly statelessFragmentDefaultActions: string[] = [];

  /**
   * The Default actions for packets that don't match a stateful rule
   */
  public readonly statefulDefaultActions: string[] = [];

  /**
   * The stateless rule groups in this policy
   */
  public readonly statelessRuleGroups: StatelessRuleGroupList[] = [];

  /**
   * The stateful rule groups in this policy
   */
  public readonly statefulRuleGroups: StatefulRuleGroupList[] = [];

  /**
   * The TLS Inspection Configuration
   */
  public readonly tlsInspectionConfiguration?: ITLSInspectionConfiguration;

  /**
   * Tags to be added to the policy.
   */
  public readonly tags: core.Tag[];

  /**
   * The stateful engine options for the firewall policy.
   */
  public readonly statefulEngineOptions?: CfnFirewallPolicy.StatefulEngineOptionsProperty;

  /**
   * Whether the user explicitly set a ruleOrder.
   * When false, the ruleOrder will be inferred from the first stateful rule group added.
   */
  private readonly explicitRuleOrder: boolean;

  /**
   * The resolved ruleOrder for the policy.
   * Starts as the user-provided value or undefined (to be inferred later).
   */
  private resolvedRuleOrder?: string;

  /**
   *
   * @param scope
   * @param id
   * @param props
   */
  constructor(scope: Construct, id: string, props: FirewallPolicyProps) {
    super(scope, id, {
      physicalName: props.firewallPolicyName,
    });

    this.statelessDefaultActions = props.statelessDefaultActions || [];
    this.statelessFragmentDefaultActions =
      props.statelessFragmentDefaultActions || [];
    this.statefulDefaultActions = props.statefulDefaultActions || [];

    this.statelessRuleGroups = [];
    this.statefulRuleGroups = [];
    this.tlsInspectionConfiguration = props.tlsInspectionConfiguration;
    this.tags = props.tags || [];

    // Build statefulEngineOptions from convenience props or use L1 override
    if (
      props.statefulEngineOptions &&
      (props.ruleOrder || props.streamExceptionPolicy || props.flowTimeouts)
    ) {
      throw new Error(
        "Cannot specify both statefulEngineOptions and individual ruleOrder/streamExceptionPolicy/flowTimeouts properties. " +
          "Use either the L1 statefulEngineOptions or the convenience properties, not both.",
      );
    }

    // Track whether the user explicitly set a ruleOrder
    this.explicitRuleOrder = !!(props.statefulEngineOptions || props.ruleOrder);

    if (props.statefulEngineOptions) {
      this.statefulEngineOptions = props.statefulEngineOptions;
      this.resolvedRuleOrder = props.statefulEngineOptions.ruleOrder;
    } else {
      // If the user explicitly set a ruleOrder, use it immediately.
      // Otherwise, resolvedRuleOrder stays undefined until the first rule group is added.
      this.resolvedRuleOrder = props.ruleOrder;
      this.statefulEngineOptions = {
        ruleOrder: props.ruleOrder,
        streamExceptionPolicy: props.streamExceptionPolicy,
        flowTimeouts: props.flowTimeouts,
      };
    }

    // Adding Validations

    /**
     * Validate enableTlsSessionHolding requires a TLS Inspection Configuration
     */
    if (props.enableTlsSessionHolding && !props.tlsInspectionConfiguration) {
      throw new Error(
        "enableTlsSessionHolding requires an associated TLS Inspection configuration",
      );
    }

    /**
     * Validate policyId
     */
    if (props.firewallPolicyName !== undefined) {
      if (/^[\dA-Za-z-]+$/.test(props.firewallPolicyName)) {
        this.firewallPolicyId = props.firewallPolicyName;
      } else {
        throw new Error(
          "firewallPolicyName must contain only letters, numbers, and dashes, " +
            `got: '${props.firewallPolicyName}'`,
        );
      }
    }

    /**
     * Validating Stateless Default Actions
     */
    if (props.statelessDefaultActions !== undefined) {
      // Ensure only one standard action is provided.
      if (
        this.validateOnlyOne(
          StatelessStandardAction,
          props.statelessDefaultActions,
        )
      ) {
        this.statelessDefaultActions = props.statelessDefaultActions;
      } else {
        throw new Error(
          "Only one standard action can be provided for the StatelessDefaultAction, all other actions must be custom",
        );
      }
    }

    /**
     * Validating Stateless Fragment Default Actions
     */
    if (props.statelessFragmentDefaultActions !== undefined) {
      // Ensure only one standard action is provided.
      if (
        this.validateOnlyOne(
          StatelessStandardAction,
          props.statelessFragmentDefaultActions,
        )
      ) {
        this.statelessFragmentDefaultActions =
          props.statelessFragmentDefaultActions;
      } else {
        throw new Error(
          "Only one standard action can be provided for the StatelessFragmentDefaultAction, all other actions must be custom",
        );
      }
    }

    /**
     * Validating Stateful Strict Default Actions
     */
    if (props.statefulDefaultActions !== undefined) {
      // Ensure only one standard action is provided.
      if (
        this.validateOnlyOne(StatefulStrictAction, props.statefulDefaultActions)
      ) {
        this.statefulDefaultActions = props.statefulDefaultActions;
      } else {
        throw new Error(
          "Only one strict action can be provided for the StatefulDefaultAction, all other actions must be custom",
        );
      }
    }

    /**
     * Add stateless rule groups via the add method (which validates unique priorities)
     */
    for (const ruleGroup of props.statelessRuleGroups || []) {
      this.addStatelessRuleGroup(ruleGroup);
    }

    /**
     * Add stateful rule groups via the add method (which validates priority and uniqueness)
     */
    for (const ruleGroup of props.statefulRuleGroups || []) {
      this.addStatefulRuleGroup(ruleGroup);
    }

    // Auto define stateless default actions?
    //const statelessDefaultActions = props.statelessDefaultActions || [StatelessStandardAction.DROP];

    // Auto define stateless fragment default actions?
    //const statelessFragmentDefaultActions = props.statelessFragmentDefaultActions || [StatelessStandardAction.DROP];

    // Auto define stateful default actions?
    // Only valid when using the strict order rule
    //const statefulDefaultActions = props.statefulDefaultActions || [statefulStrictAction.ALERT_ESTABLISHED]

    // Auto define stateless rule group?
    //const statelessRuleGroup = props.statelessRuleGroups || [new StatelessRuleGroup(priority=10,...)];

    // Auto define stateful rule group?
    //const statefulRuleGroup = props.statefulRuleGroups || [new StatefulRuleGroup5Tuple(priority=10,...)];

    const resourcePolicyProperty: CfnFirewallPolicy.FirewallPolicyProperty = {
      statelessDefaultActions: this.statelessDefaultActions,
      statelessFragmentDefaultActions: this.statelessFragmentDefaultActions,
      // The properties below are optional.
      statefulDefaultActions: this.statefulDefaultActions,
      statefulEngineOptions: core.Lazy.any({
        produce: () => this.buildStatefulEngineOptions(),
      }),
      statefulRuleGroupReferences: core.Lazy.any({
        produce: () => this.buildStatefulRuleGroupReferences(),
      }),
      statelessCustomActions: props.statelessCustomActions,
      statelessRuleGroupReferences: core.Lazy.any({
        produce: () => this.buildStatelessRuleGroupReferences(),
      }),
      tlsInspectionConfigurationArn:
        props.tlsInspectionConfiguration?.tlsInspectionConfigurationArn,
      enableTlsSessionHolding: props.enableTlsSessionHolding,
      policyVariables: props.policyVariables,
    };

    const resourceProps: CfnFirewallPolicyProps = {
      firewallPolicy: resourcePolicyProperty,
      firewallPolicyName: props.firewallPolicyName || id,
      description: props.description,
      tags: props.tags,
    };

    const resource: CfnFirewallPolicy = new CfnFirewallPolicy(
      this,
      props.firewallPolicyName || id,
      resourceProps,
    );

    this.firewallPolicyId = this.getResourceNameAttribute(resource.ref);

    this.firewallPolicyArn = this.getResourceArnAttribute(
      resource.attrFirewallPolicyArn,
      {
        service: "network-firewall",
        resource: "firewall-policy",
        resourceName: this.firewallPolicyId,
      },
    );
  }

  /**
   * Add a stateless rule group to the policy
   * @param ruleGroup The stateless rule group to add to the policy
   */
  public addStatelessRuleGroup(ruleGroup: StatelessRuleGroupList) {
    // Check for unique priority
    if (
      ruleGroup.priority !== undefined &&
      this.statelessRuleGroups.some((r) => r.priority === ruleGroup.priority)
    ) {
      throw new Error(
        "Priority must be unique, received duplicate priority on stateless group",
      );
    }
    this.statelessRuleGroups.push(ruleGroup);
  }

  /**
   * Add a stateful rule group to the policy
   * @param ruleGroup The stateful rule group to add to the policy
   */
  public addStatefulRuleGroup(ruleGroup: StatefulRuleGroupList) {
    // If no explicit ruleOrder was set and this is the first rule group,
    // infer the ruleOrder from the rule group's ruleOrder.
    if (!this.explicitRuleOrder && this.statefulRuleGroups.length === 0) {
      if (ruleGroup.ruleGroup.ruleOrder) {
        this.resolvedRuleOrder = ruleGroup.ruleGroup.ruleOrder;
      }
    }

    // Validate that the rule group's ruleOrder matches the policy's effective ruleOrder
    if (
      ruleGroup.ruleGroup.ruleOrder &&
      ruleGroup.ruleGroup.ruleOrder !== this.getEffectiveRuleOrder()
    ) {
      throw new Error(`Stateful rule group does not match policy rule order.`);
    }

    if (
      this.getEffectiveRuleOrder() ===
        StatefulEngineOptionsRuleOrder.STRICT_ORDER &&
      ruleGroup.priority === undefined
    ) {
      throw new Error(
        "All stateful rule groups must have a priority set when using STRICT_ORDER engine options",
      );
    }
    // Check for unique priority
    if (
      ruleGroup.priority !== undefined &&
      this.statefulRuleGroups.some((r) => r.priority === ruleGroup.priority)
    ) {
      throw new Error(
        "Priority must be unique, received duplicate priority on stateful group",
      );
    }
    this.statefulRuleGroups.push(ruleGroup);
  }

  /**
   * Returns the effective rule order, resolving the lazy default.
   * If the user did not explicitly set a ruleOrder and no rule group has been added yet,
   * defaults to STRICT_ORDER.
   */
  private getEffectiveRuleOrder(): string {
    return (
      this.resolvedRuleOrder || StatefulEngineOptionsRuleOrder.STRICT_ORDER
    );
  }

  /**
   * Builds the statefulEngineOptions at synthesis time, resolving the ruleOrder.
   */
  private buildStatefulEngineOptions(): CfnFirewallPolicy.StatefulEngineOptionsProperty {
    const effectiveRuleOrder = this.getEffectiveRuleOrder();

    // statefulDefaultActions is only valid with STRICT_ORDER
    if (
      this.statefulDefaultActions.length > 0 &&
      effectiveRuleOrder !== StatefulEngineOptionsRuleOrder.STRICT_ORDER
    ) {
      throw new Error(
        "statefulDefaultActions can only be used with STRICT_ORDER rule order, " +
          `but the effective rule order is '${effectiveRuleOrder}'`,
      );
    }

    return {
      ...this.statefulEngineOptions,
      ruleOrder: effectiveRuleOrder,
    };
  }

  /**
   * Builds the stateless rule group list object from current state
   * uses this.buildRuleGroupReferences
   */
  private buildStatelessRuleGroupReferences(): CfnFirewallPolicy.StatelessRuleGroupReferenceProperty[] {
    let ruleGroupReferences: CfnFirewallPolicy.StatelessRuleGroupReferenceProperty[] =
      [];
    let ruleGroup: StatelessRuleGroupList;
    for (ruleGroup of this.statelessRuleGroups) {
      ruleGroupReferences.push({
        priority: ruleGroup.priority,
        resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
      });
    }
    return ruleGroupReferences;
  }

  /**
   * Builds the stateful rule group list object from current state
   * uses this.buildRuleGroupReferences
   */
  private buildStatefulRuleGroupReferences(): CfnFirewallPolicy.StatefulRuleGroupReferenceProperty[] {
    let ruleGroupReferences: CfnFirewallPolicy.StatefulRuleGroupReferenceProperty[] =
      [];
    let ruleGroup: StatefulRuleGroupList;
    for (ruleGroup of this.statefulRuleGroups) {
      const ref: CfnFirewallPolicy.StatefulRuleGroupReferenceProperty = {
        resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
        priority: ruleGroup.priority,
        deepThreatInspection: ruleGroup.deepThreatInspection,
        override: ruleGroup.override,
      };
      ruleGroupReferences.push(ref);
    }
    return ruleGroupReferences;
  }

  /**
   * Converts a Stateful(less)RuleGroupList to a Stateful(less)RuleGroupReferenceProperty
   */
  /*private buildRuleGroupReferences(ruleGroups:(StatefulRuleGroupList|StatelessRuleGroupList)[]) {
    let ruleGroupReferences:CfnFirewallPolicy.StatelessRuleGroupReferenceProperty[]|CfnFirewallPolicy.StatefulRuleGroupReferenceProperty = [];
    let ruleGroup:StatefulRuleGroupList|StatelessRuleGroupList;
    for (ruleGroup of ruleGroups) {
      ruleGroupReferences.push({
        priority: ruleGroup.priority,
        resourceArn: ruleGroup.ruleGroup.ruleGroupArn,
      });
    }
    return ruleGroupReferences;
  }*/

  /**
   * Validates that only one occurrence of the enumeration is found in the values.
   * This is for verifying only one standard default action is used in a list.
   * @param enumeration
   * @param values
   */
  private validateOnlyOne(enumeration: any, values: string[]): boolean {
    let oneFound: boolean = false;
    let value: string;
    for (value of values) {
      if (Object.values<string>(enumeration).includes(value)) {
        if (oneFound) {
          return false;
        }
        oneFound = true;
      }
    }
    return true;
  }
}
