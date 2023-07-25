import { Construct } from 'constructs';
import { StatelessStandardAction, StatefulStrictAction } from './actions';
import { CfnFirewallPolicy } from 'aws-cdk-lib/aws-networkfirewall';
import { IStatefulRuleGroup, IStatelessRuleGroup } from './rule-group';
import * as core from 'aws-cdk-lib/core';
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
     *
     * @attribute
     */
    readonly firewallPolicyArn: string;
    /**
     * The phyiscal name of the firewall policy.
     *
     * @attribute
     */
    readonly firewallPolicyId: string;
}
declare abstract class FirewallPolicyBase extends core.Resource implements IFirewallPolicy {
    /**
     * The Arn of the policy.
     *
     * @attribute
     */
    abstract readonly firewallPolicyArn: string;
    /**
     * The phyiscal name of the firewall policy.
     *
     * @attribute
     */
    abstract readonly firewallPolicyId: string;
}
/**
 * The Properties for defining a Firewall policy
 */
export interface FirewallPolicyProps {
    /**
     * The descriptive name of the firewall policy.
     * You can't change the name of a firewall policy after you create it.
     *
     * @default - CloudFormation-generated name
     */
    readonly firewallPolicyName?: string;
    /**
     * The actions to take on a packet if it doesn't match any of the stateless rules in the policy.
     */
    readonly statelessDefaultActions: (StatelessStandardAction | string)[];
    /**
     * The actions to take on a fragmented packet if it doesn't match any of the stateless rules in the policy.
     */
    readonly statelessFragmentDefaultActions: (StatelessStandardAction | string)[];
    /**
     * The default actions to take on a packet that doesn't match any stateful rules.
     * The stateful default action is optional, and is only valid when using the strict rule order
     *
     * @default - undefined
     */
    readonly statefulDefaultActions?: (StatefulStrictAction | string)[];
    /**
     * Additional options governing how Network Firewall handles stateful rules.
     * The stateful rule groups that you use in your policy must have stateful rule options settings that are compatible with these settings
     *
     * @default - undefined
     */
    readonly statefulEngineOptions?: CfnFirewallPolicy.StatefulEngineOptionsProperty;
    /**
     * The stateful rule groups that are used in the policy.
     *
     * @default - undefined
     */
    readonly statefulRuleGroups?: StatefulRuleGroupList[];
    /**
     * The custom action definitions that are available for use in the firewall policy's statelessDefaultActions setting.
     *
     * @default - undefined
     */
    readonly statelessCustomActions?: CfnFirewallPolicy.CustomActionProperty[];
    /**
     *References to the stateless rule groups that are used in the policy.
     *
     * @default - undefined
     */
    readonly statelessRuleGroups?: StatelessRuleGroupList[];
    /**
     * The description of the policy.
     *
     * @default - undefined
     */
    readonly description?: string;
}
/**
 * Defines a Firewall Policy in the stack
 * @resource AWS::NetworkFirewall::FirewallPolicy
 */
export declare class FirewallPolicy extends FirewallPolicyBase {
    /**
     * Reference existing firewall policy name
     * @param firewallPolicyName The name of the existing firewall policy
     */
    static fromFirewallPolicyName(scope: Construct, id: string, firewallPolicyName: string): IFirewallPolicy;
    /**
     * Reference existing firewall policy by Arn
     * @param firewallPolicyArn the ARN of the existing firewall policy
     */
    static fromFirewallPolicyArn(scope: Construct, id: string, firewallPolicyArn: string): IFirewallPolicy;
    readonly firewallPolicyArn: string;
    readonly firewallPolicyId: string;
    /**
     * The Default actions for packets that don't match a stateless rule
     */
    readonly statelessDefaultActions: string[];
    /**
     * The Default actions for fragment packets that don't match a stateless rule
     */
    readonly statelessFragmentDefaultActions: string[];
    /**
     * The Default actions for packets that don't match a stateful rule
     */
    readonly statefulDefaultActions: string[];
    /**
     * The stateless rule groups in this policy
     */
    readonly statelessRuleGroups: StatelessRuleGroupList[];
    /**
     * The stateful rule groups in this policy
     */
    readonly statefulRuleGroups: StatefulRuleGroupList[];
    constructor(scope: Construct, id: string, props: FirewallPolicyProps);
    /**
     * Add a stateless rule group to the policy
     *
     * @param ruleGroup The stateless rule group to add to the policy
     */
    addStatelessRuleGroup(ruleGroup: StatelessRuleGroupList): void;
    /**
     * Add a stateful rule group to the policy
     *
     * @param ruleGroup The stateful rule group to add to the policy
     */
    addStatefulRuleGroup(ruleGroup: StatefulRuleGroupList): void;
    /**
     * Builds the stateless rule group list object from current state
     * uses this.buildRuleGroupReferences
     */
    private buildStatelessRuleGroupReferences;
    /**
     * Builds the stateful rule group list object from current state
     * uses this.buildRuleGroupReferences
     */
    private buildStatefulRuleGroupReferences;
    /**
     * Converts a Stateful(less)RuleGroupList to a Stateful(less)RuleGroupReferenceProperty
     */
    /**
     * To validate a set of rule groups to ensure they have unqiue priorities
     */
    private validateUniquePriority;
    /**
     * Validates that only one occurance of the enumeration is found in the values.
     * This is for verifying only one standard default action is used in a list.
     */
    private validateOnlyOne;
}
export {};
